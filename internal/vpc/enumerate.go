package vpc

import (
	"context"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	vpcfern "github.com/Method-Security/methodaws/generated/go/vpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateVPC(ctx context.Context, awsConfig aws.Config, config vpcfern.VpcEnumerateConfig) *vpcfern.VpcEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting VPC enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &vpcfern.VpcEnumerateReport{
		Config: &config,
		Result: &vpcfern.VpcEnumerateResult{},
	}

	var allVPCs []*vpcfern.VpcInstance
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing VPCs and Subnets in region", svc1log.SafeParam("region", region))
		vpcs, errors := enumerateVPCWithSubnetsForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating VPCs/Subnets in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allVPCs = append(allVPCs, vpcs...)
		allErrors = append(allErrors, errors...)

		totalSubnets := 0
		for _, vpcInstance := range vpcs {
			if vpcInstance.Resources != nil && vpcInstance.Resources.Subnets != nil {
				totalSubnets += len(vpcInstance.Resources.Subnets)
			}
		}

		log.Info("Successfully processed VPCs and Subnets in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("vpcCount", len(vpcs)),
			svc1log.SafeParam("subnetCount", totalSubnets))
	}

	// Marshal report
	if len(allVPCs) > 0 {
		report.Result.Vpcs = allVPCs
	}
	report.Errors = allErrors
	return report
}

func enumerateVPCWithSubnetsForRegion(ctx context.Context, cfg aws.Config, region string) ([]*vpcfern.VpcInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	svc := ec2.NewFromConfig(regionCfg)

	var vpcs []*vpcfern.VpcInstance
	var errors []string

	// First, get all VPCs
	vpcPaginator := ec2.NewDescribeVpcsPaginator(svc, &ec2.DescribeVpcsInput{})
	vpcMap := make(map[string]*vpcfern.VpcInstance)

	for vpcPaginator.HasMorePages() {
		result, err := vpcPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve VPCs page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		for _, vpc := range result.Vpcs {
			if vpc.VpcId == nil {
				log.Warn("VPC ID is nil", svc1log.SafeParam("vpc", vpc))
				errors = append(errors, "VPC ID is nil")
				continue
			}
			vpcInstance, errs := convertAWSVPCToFern(vpc, region)
			if vpcInstance != nil {
				vpcs = append(vpcs, vpcInstance)
				vpcMap[vpcInstance.Identification.Id] = vpcInstance
			}
			errors = append(errors, errs...)
		}
	}

	// Then, get all subnets and associate them with VPCs
	subnetPaginator := ec2.NewDescribeSubnetsPaginator(svc, &ec2.DescribeSubnetsInput{})

	for subnetPaginator.HasMorePages() {
		result, err := subnetPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve Subnets page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		for _, subnet := range result.Subnets {
			// check if the subnet has an ID
			if subnet.SubnetId == nil {
				log.Warn("Subnet ID is nil", svc1log.SafeParam("subnet", subnet))
				errors = append(errors, "Subnet ID is nil")
				continue
			}

			// Convert the subnet to a Fern subnet
			subnetConverted, errs := convertAWSSubnetToFern(subnet, region)
			if subnetConverted != nil && subnet.VpcId != nil {
				// Find the VPC this subnet belongs to using the AWS subnet's VPC ID
				if vpcInstance, exists := vpcMap[*subnet.VpcId]; exists {
					if vpcInstance.Resources == nil {
						vpcInstance.Resources = &vpcfern.VpcResourceInfo{}
					}
					if vpcInstance.Resources.Subnets == nil {
						vpcInstance.Resources.Subnets = []*vpcfern.Subnet{}
					}
					vpcInstance.Resources.Subnets = append(vpcInstance.Resources.Subnets, subnetConverted)
				}
			}
			errors = append(errors, errs...)
		}
	}

	return vpcs, errors
}

// convertAWSVPCToFern converts an AWS VPC to a Fern VPC
func convertAWSVPCToFern(awsVPC ec2types.Vpc, region string) (*vpcfern.VpcInstance, []string) {
	errors := []string{}
	if awsVPC.VpcId == nil {
		return nil, errors
	}

	// Convert AWS VPC tags to Fern tags and extract name
	var tags []*common.Tag
	var name *string
	for _, tag := range awsVPC.Tags {
		tags = append(tags, &common.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		})
		// Extract name from "Name" tag
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			name = tag.Value
		}
	}

	// Convert instance tenancy
	var tenancy *vpcfern.Tenancy
	if awsVPC.InstanceTenancy != "" {
		if t, err := vpcfern.NewTenancyFromString(strings.ToUpper(string(awsVPC.InstanceTenancy))); err == nil {
			tenancy = &t
		} else {
			errors = append(errors, err.Error())
		}
	}

	// Convert VPC state
	var state *vpcfern.VpcState
	if awsVPC.State != "" {
		if s, err := vpcfern.NewVpcStateFromString(strings.ToUpper(string(awsVPC.State))); err == nil {
			state = &s
		} else {
			errors = append(errors, err.Error())
		}
	}

	// Convert CIDR block associations (both IPv4 and IPv6)
	var cidrAssociations []*vpcfern.VpcCidrBlockAssociation

	// Add IPv4 CIDR block associations
	for _, assoc := range awsVPC.CidrBlockAssociationSet {
		cidrAssociations = append(cidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId: aws.ToString(assoc.AssociationId),
			CidrBlock:     aws.ToString(assoc.CidrBlock),
		})
	}

	// Add IPv6 CIDR block associations
	for _, assoc := range awsVPC.Ipv6CidrBlockAssociationSet {
		cidrAssociations = append(cidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId: aws.ToString(assoc.AssociationId),
			CidrBlock:     aws.ToString(assoc.Ipv6CidrBlock),
		})
	}

	vpc := &vpcfern.VpcInstance{
		Identification: &vpcfern.VpcIdentificationInfo{
			Id:     *awsVPC.VpcId,
			Region: region,
			Name:   name,
		},
		Configuration: &vpcfern.VpcConfigurationInfo{
			CreationCidrBlock: awsVPC.CidrBlock,
			DhcpOptionsId:     awsVPC.DhcpOptionsId,
			InstanceTenancy:   tenancy,
			IsDefault:         awsVPC.IsDefault,
			OwnerId:           awsVPC.OwnerId,
			State:             state,
			Tags:              tags,
		},
		Resources: &vpcfern.VpcResourceInfo{
			Subnets:                 []*vpcfern.Subnet{},
			CidrBlockAssociationSet: cidrAssociations,
		},
	}

	return vpc, errors
}

// convertAWSSubnetToFern converts an AWS Subnet to a Fern Subnet
func convertAWSSubnetToFern(awsSubnet ec2types.Subnet, region string) (*vpcfern.Subnet, []string) {
	errors := []string{}
	// Convert AWS Subnet tags to Fern tags and extract name
	var tags []*common.Tag
	var name *string
	for _, tag := range awsSubnet.Tags {
		tags = append(tags, &common.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		})
		// Extract name from "Name" tag
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			name = tag.Value
		}
	}

	// Convert subnet state
	var state *vpcfern.SubnetState
	if awsSubnet.State != "" {
		if s, err := vpcfern.NewSubnetStateFromString(strings.ToUpper(string(awsSubnet.State))); err == nil {
			state = &s
		} else {
			errors = append(errors, err.Error())
		}
	}

	// Convert available IP address count from *int32 to *int
	var availableIPCount *int
	if awsSubnet.AvailableIpAddressCount != nil {
		count := int(*awsSubnet.AvailableIpAddressCount)
		availableIPCount = &count
	}

	// Convert EnableLniAtDeviceIndex from *int32 to *int
	var enableLni *int
	if awsSubnet.EnableLniAtDeviceIndex != nil {
		lni := int(*awsSubnet.EnableLniAtDeviceIndex)
		enableLni = &lni
	}

	var privateDNSOptions *vpcfern.PrivateDnsNameOptionsOnLaunch
	if awsSubnet.PrivateDnsNameOptionsOnLaunch != nil {
		privateDNSOptions = &vpcfern.PrivateDnsNameOptionsOnLaunch{
			EnableResourceNameDnsARecord:    awsSubnet.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsARecord,
			EnableResourceNameDnsAaaaRecord: awsSubnet.PrivateDnsNameOptionsOnLaunch.EnableResourceNameDnsAAAARecord,
		}
		if awsSubnet.PrivateDnsNameOptionsOnLaunch.HostnameType != "" {
			hostnameType, err := vpcfern.NewSubnetHostnameTypeFromString(
				strings.ToUpper(strings.ReplaceAll(string(awsSubnet.PrivateDnsNameOptionsOnLaunch.HostnameType), "-", "_")),
			)
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				privateDNSOptions.HostnameType = &hostnameType
			}
		}
	}

	// Create AvailabilityZone object from AWS data
	var availabilityZone *vpcfern.AvailabilityZone
	if awsSubnet.AvailabilityZone != nil || awsSubnet.AvailabilityZoneId != nil {
		availabilityZone = &vpcfern.AvailabilityZone{
			ZoneName: awsSubnet.AvailabilityZone,
			ZoneId:   awsSubnet.AvailabilityZoneId,
		}
	}

	// Convert subnet IPv6 CIDR block associations
	var subnetCidrAssociations []*vpcfern.VpcCidrBlockAssociation

	for _, assoc := range awsSubnet.Ipv6CidrBlockAssociationSet {
		subnetCidrAssociations = append(subnetCidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId: aws.ToString(assoc.AssociationId),
			CidrBlock:     aws.ToString(assoc.Ipv6CidrBlock),
		})
	}

	subnet := &vpcfern.Subnet{
		Identification: &vpcfern.SubnetIdentificationInfo{
			Id:     *awsSubnet.SubnetId,
			Arn:    awsSubnet.SubnetArn,
			Name:   name,
			Region: region,
		},
		Configuration: &vpcfern.SubnetConfigurationInfo{
			AssignIpv6AddressOnCreation:   awsSubnet.AssignIpv6AddressOnCreation,
			AvailabilityZone:              availabilityZone,
			AvailableIpAddressCount:       availableIPCount,
			CustomerOwnedIpv4Pool:         awsSubnet.CustomerOwnedIpv4Pool,
			DefaultForAz:                  awsSubnet.DefaultForAz,
			EnableDns64:                   awsSubnet.EnableDns64,
			EnableLniAtDeviceIndex:        enableLni,
			Ipv6Native:                    awsSubnet.Ipv6Native,
			MapCustomerOwnedIpOnLaunch:    awsSubnet.MapCustomerOwnedIpOnLaunch,
			MapPublicIpOnLaunch:           awsSubnet.MapPublicIpOnLaunch,
			OutpostArn:                    awsSubnet.OutpostArn,
			OwnerId:                       awsSubnet.OwnerId,
			PrivateDnsNameOptionsOnLaunch: privateDNSOptions,
			State:                         state,
			Tags:                          tags,
		},
		Resources: &vpcfern.SubnetResourceInfo{
			CidrBlock:               awsSubnet.CidrBlock,
			CidrBlockAssociationSet: subnetCidrAssociations,
		},
	}

	return subnet, errors
}

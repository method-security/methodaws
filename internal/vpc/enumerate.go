package vpc

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	vpcfern "github.com/Method-Security/methodaws/generated/go/vpc"
	"github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
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
	if strings.TrimSpace(region) == "" {
		return nil, []string{"Cannot enumerate VPCs/subnets without a region"}
	}
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
			errors = append(errors, fmt.Sprintf("DescribeVpcs in %s: %v", region, err))
			break
		}
		if result == nil {
			errors = append(errors, fmt.Sprintf("DescribeVpcs in %s returned no response", region))
			break
		}

		for _, vpc := range result.Vpcs {
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
			errors = append(errors, fmt.Sprintf("DescribeSubnets in %s: %v", region, err))
			break
		}
		if result == nil {
			errors = append(errors, fmt.Sprintf("DescribeSubnets in %s returned no response", region))
			break
		}

		for _, subnet := range result.Subnets {
			subnetConverted, errs := convertAWSSubnetToFern(subnet, region)
			errors = append(errors, errs...)
			if subnetConverted == nil {
				continue
			}
			if !hasValue(subnet.VpcId) {
				errors = append(errors, fmt.Sprintf("Subnet %s in %s has no parent VPC ID", subnetConverted.Identification.Id, region))
				continue
			}
			vpcInstance, exists := vpcMap[*subnet.VpcId]
			if !exists {
				errors = append(errors, fmt.Sprintf("Skipping subnet %s in %s: parent VPC %s was not collected with a complete identity", subnetConverted.Identification.Id, region, *subnet.VpcId))
				continue
			}
			if vpcInstance.Resources == nil {
				vpcInstance.Resources = &vpcfern.VpcResourceInfo{}
			}
			vpcInstance.Resources.Subnets = append(vpcInstance.Resources.Subnets, subnetConverted)
		}
	}

	return vpcs, errors
}

// convertAWSVPCToFern converts an AWS VPC to a Fern VPC
func convertAWSVPCToFern(awsVPC ec2types.Vpc, region string) (*vpcfern.VpcInstance, []string) {
	errors := []string{}
	if !hasValue(awsVPC.VpcId) || strings.TrimSpace(region) == "" {
		return nil, []string{fmt.Sprintf("Cannot identify VPC: missing VPC ID or region (id=%q, region=%q)", aws.ToString(awsVPC.VpcId), region)}
	}
	vpcARN, err := resourceARN(region, "vpc", *awsVPC.VpcId, awsVPC.OwnerId, nil)
	if err != nil {
		return nil, []string{fmt.Sprintf("Cannot identify VPC %s in %s: %v", *awsVPC.VpcId, region, err)}
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
		var associationState string
		if assoc.CidrBlockState != nil {
			associationState = string(assoc.CidrBlockState.State)
		}
		converted, err := convertCIDRAssociation(assoc.AssociationId, assoc.CidrBlock, associationState, false)
		if err != nil {
			errors = append(errors, fmt.Sprintf("VPC %s in %s IPv4 association: %v", *awsVPC.VpcId, region, err))
			continue
		}
		cidrAssociations = append(cidrAssociations, converted)
	}

	// Add IPv6 CIDR block associations
	for _, assoc := range awsVPC.Ipv6CidrBlockAssociationSet {
		var associationState string
		if assoc.Ipv6CidrBlockState != nil {
			associationState = string(assoc.Ipv6CidrBlockState.State)
		}
		converted, err := convertCIDRAssociation(assoc.AssociationId, assoc.Ipv6CidrBlock, associationState, true)
		if err != nil {
			errors = append(errors, fmt.Sprintf("VPC %s in %s IPv6 association: %v", *awsVPC.VpcId, region, err))
			continue
		}
		cidrAssociations = append(cidrAssociations, converted)
	}
	creationCIDR, err := validatedCIDR(awsVPC.CidrBlock, false)
	if err != nil {
		errors = append(errors, fmt.Sprintf("VPC %s in %s primary CIDR: %v", *awsVPC.VpcId, region, err))
	}

	vpc := &vpcfern.VpcInstance{
		Identification: &vpcfern.VpcIdentificationInfo{
			Id:     *awsVPC.VpcId,
			Arn:    vpcARN,
			Region: region,
			Name:   name,
		},
		Configuration: &vpcfern.VpcConfigurationInfo{
			CreationCidrBlock: creationCIDR,
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
	if !hasValue(awsSubnet.SubnetId) || strings.TrimSpace(region) == "" {
		return nil, []string{fmt.Sprintf("Cannot identify subnet: missing subnet ID or region (id=%q, region=%q)", aws.ToString(awsSubnet.SubnetId), region)}
	}
	subnetARN, err := resourceARN(region, "subnet", *awsSubnet.SubnetId, awsSubnet.OwnerId, awsSubnet.SubnetArn)
	if err != nil {
		return nil, []string{fmt.Sprintf("Cannot identify subnet %s in %s: %v", *awsSubnet.SubnetId, region, err)}
	}
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
		if s, err := vpcfern.NewSubnetStateFromString(strings.ToUpper(strings.ReplaceAll(string(awsSubnet.State), "-", "_"))); err == nil {
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
		if hasValue(awsSubnet.AvailabilityZoneId) {
			availabilityZone = &vpcfern.AvailabilityZone{
				ZoneName: awsSubnet.AvailabilityZone,
				ZoneId:   *awsSubnet.AvailabilityZoneId,
			}
		} else {
			errors = append(errors, fmt.Sprintf("Subnet %s in %s availability zone has no zone ID", *awsSubnet.SubnetId, region))
		}
	}

	// Convert subnet IPv6 CIDR block associations
	var subnetCidrAssociations []*vpcfern.VpcCidrBlockAssociation

	for _, assoc := range awsSubnet.Ipv6CidrBlockAssociationSet {
		var associationState string
		if assoc.Ipv6CidrBlockState != nil {
			associationState = string(assoc.Ipv6CidrBlockState.State)
		}
		converted, err := convertCIDRAssociation(assoc.AssociationId, assoc.Ipv6CidrBlock, associationState, true)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Subnet %s in %s IPv6 association: %v", *awsSubnet.SubnetId, region, err))
			continue
		}
		subnetCidrAssociations = append(subnetCidrAssociations, converted)
	}
	cidr, err := validatedCIDR(awsSubnet.CidrBlock, false)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Subnet %s in %s primary CIDR: %v", *awsSubnet.SubnetId, region, err))
	}

	subnet := &vpcfern.Subnet{
		Identification: &vpcfern.SubnetIdentificationInfo{
			Id:     *awsSubnet.SubnetId,
			Arn:    subnetARN,
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
			CidrBlock:               cidr,
			CidrBlockAssociationSet: subnetCidrAssociations,
		},
	}

	return subnet, errors
}

func hasValue(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

// Resource ownership comes from the response, never the caller's account.
func resourceARN(region, resourceType, id string, ownerID, reportedARN *string) (string, error) {
	owner := strings.TrimSpace(aws.ToString(ownerID))
	if reportedARN != nil {
		parsed, err := arn.Parse(*reportedARN)
		if err != nil || strings.TrimSpace(parsed.AccountID) == "" {
			return "", fmt.Errorf("invalid %s ARN %q", resourceType, *reportedARN)
		}
		if owner != "" && parsed.AccountID != owner {
			return "", fmt.Errorf("%s ARN owner does not match reported owner", resourceType)
		}
		expected, err := utils.BuildRegionalARN(region, "ec2", parsed.AccountID, resourceType+"/"+id)
		if err != nil {
			return "", err
		}
		if *reportedARN != expected {
			return "", fmt.Errorf("%s ARN does not match its resource ID, region, service or partition", resourceType)
		}
		return expected, nil
	}
	if owner == "" {
		return "", fmt.Errorf("missing owner account ID for %s ARN", resourceType)
	}
	return utils.BuildRegionalARN(region, "ec2", owner, resourceType+"/"+id)
}

func validatedCIDR(value *string, ipv6 bool) (*string, error) {
	if value == nil {
		return nil, nil
	}
	prefix, err := netip.ParsePrefix(*value)
	if err != nil || prefix.Addr().Is6() != ipv6 || prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("invalid CIDR %q (IPv6=%t)", *value, ipv6)
	}
	return value, nil
}

func convertCIDRAssociation(id, cidr *string, state string, ipv6 bool) (*vpcfern.VpcCidrBlockAssociation, error) {
	if !hasValue(id) {
		return nil, fmt.Errorf("missing association ID")
	}
	if !hasValue(cidr) {
		return nil, fmt.Errorf("association %s has no CIDR", *id)
	}
	if _, err := validatedCIDR(cidr, ipv6); err != nil {
		return nil, fmt.Errorf("association %s: %w", *id, err)
	}
	association := &vpcfern.VpcCidrBlockAssociation{AssociationId: *id, CidrBlock: *cidr}
	if state != "" {
		association.State = &state
	}
	return association, nil
}

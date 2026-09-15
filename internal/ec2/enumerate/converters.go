package enumerate

import (
	"context"
	"fmt"
	"strings"

	"github.com/Method-Security/methodaws/generated/go/common"
	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// convertInstanceToFern converts AWS EC2 Instance to Fern Ec2Instance
func convertInstanceToFern(ctx context.Context, awsInstance types.Instance, region string) (*ec2.Ec2Instance, []string) {
	if aws.ToString(awsInstance.InstanceId) == "" || region == "" {
		return nil, []string{"Instance ID or region is empty"}
	}
	var errors []string

	// Convert instance state
	var state *ec2.InstanceState
	if awsInstance.State != nil {
		state = convertInstanceState(awsInstance.State.Name)
	}

	// Convert placement
	var placement *ec2.Placement
	if awsInstance.Placement != nil {
		placement = convertPlacement(awsInstance.Placement)
	}

	// Convert tags and extract name
	var tags []*ec2.Tag
	var name *string
	if len(awsInstance.Tags) > 0 {
		tags = convertTags(awsInstance.Tags)
		name = extractNameFromTags(awsInstance.Tags)
	}

	// Convert network interfaces
	var networkInterfaces []*ec2.InstanceNetworkInterface
	if len(awsInstance.NetworkInterfaces) > 0 {
		networkInterfaces, errors = convertNetworkInterfaces(ctx, awsInstance.NetworkInterfaces, region)
	}

	// Extract security group IDs
	var securityGroupIds []string
	if len(awsInstance.SecurityGroups) > 0 {
		securityGroupIds = extractSecurityGroupIds(awsInstance.SecurityGroups)
	}
	// EC2 exposes an instance profile, not the IAM role attached to that profile, so no role is inferred here.

	// Create DNS data
	var dnsData *ec2.DnsData
	if awsInstance.PrivateIpAddress != nil || awsInstance.PublicIpAddress != nil ||
		awsInstance.PrivateDnsName != nil || awsInstance.PublicDnsName != nil {
		dnsData = &ec2.DnsData{
			PrivateIpAddress: awsInstance.PrivateIpAddress,
			PublicIpAddress:  awsInstance.PublicIpAddress,
			PrivateDnsName:   awsInstance.PrivateDnsName,
			PublicDnsName:    awsInstance.PublicDnsName,
		}
	}

	// Create instance with nested structure
	instance := &ec2.Ec2Instance{
		Identification: &ec2.Ec2InstanceIdentificationInfo{
			Id:     *awsInstance.InstanceId,
			Region: region,
			Name:   name,
		},
		Configuration: &ec2.Ec2InstanceConfigurationInfo{
			State:        state,
			ImageId:      awsInstance.ImageId,
			KeyName:      awsInstance.KeyName,
			InstanceType: convertInstanceType(awsInstance.InstanceType),
			LaunchTime:   awsInstance.LaunchTime,
			Placement:    placement,
			Architecture: convertArchitecture(awsInstance.Architecture),
			Hypervisor:   convertHypervisor(awsInstance.Hypervisor),
			Platform:     convertPlatform(awsInstance.Platform),
			EbsOptimized: awsInstance.EbsOptimized,
			Tags:         tags,
		},
		Resources: &ec2.Ec2InstanceResourceInfo{
			NetworkInterfaces: networkInterfaces,
			SecurityGroupIds:  securityGroupIds,
			Dns:               dnsData,
		},
	}

	return instance, errors
}

// convertInstanceState converts AWS instance state to Fern enum
func convertInstanceState(state types.InstanceStateName) *ec2.InstanceState {
	stateStr := strings.ToUpper(strings.ReplaceAll(string(state), "-", "_"))
	fernState, err := ec2.NewInstanceStateFromString(stateStr)
	if err != nil {
		return nil
	}
	return &fernState
}

// convertInstanceType preserves AWS instance types that may be newer than this CLI.
func convertInstanceType(instanceType types.InstanceType) *string {
	if instanceType == "" {
		return nil
	}
	typeName := string(instanceType)
	return &typeName
}

// convertArchitecture converts AWS architecture to Fern enum
func convertArchitecture(arch types.ArchitectureValues) *ec2.Architecture {
	if arch == "" {
		return nil
	}
	archStr := strings.ToUpper(strings.ReplaceAll(string(arch), "-", "_"))
	fernArch := ec2.Architecture(archStr)
	return &fernArch
}

// convertHypervisor converts AWS hypervisor to Fern enum
func convertHypervisor(hypervisor types.HypervisorType) *ec2.HypervisorType {
	if hypervisor == "" {
		return nil
	}
	hypervisorStr := strings.ToUpper(string(hypervisor))
	fernHypervisor := ec2.HypervisorType(hypervisorStr)
	return &fernHypervisor
}

// convertPlatform converts AWS platform to Fern enum
func convertPlatform(platform types.PlatformValues) *ec2.PlatformValues {
	if platform == "" {
		return nil
	}
	platformStr := strings.ToUpper(string(platform))
	fernPlatform := ec2.PlatformValues(platformStr)
	return &fernPlatform
}

// convertPlacement converts AWS placement to Fern format
func convertPlacement(placement *types.Placement) *ec2.Placement {
	fernPlacement := &ec2.Placement{
		AvailabilityZone: placement.AvailabilityZone,
		Affinity:         placement.Affinity,
		GroupName:        placement.GroupName,
		HostId:           placement.HostId,
		SpreadDomain:     placement.SpreadDomain,
		GroupId:          placement.GroupId,
	}

	if placement.Tenancy != "" {
		tenancy := string(placement.Tenancy)
		fernPlacement.Tenancy = &tenancy
	}

	if placement.PartitionNumber != nil {
		partitionNum := int(*placement.PartitionNumber)
		fernPlacement.PartitionNumber = &partitionNum
	}

	fernPlacement.HostResourceGroupArn = placement.HostResourceGroupArn

	return fernPlacement
}

// convertNetworkInterfaces converts AWS network interfaces to Fern format
func convertNetworkInterfaces(ctx context.Context, interfaces []types.InstanceNetworkInterface, region string) ([]*ec2.InstanceNetworkInterface, []string) {
	var fernInterfaces []*ec2.InstanceNetworkInterface
	var errors []string
	log := svc1log.FromContext(ctx)
	for _, ni := range interfaces {
		if aws.ToString(ni.NetworkInterfaceId) == "" {
			log.Warn("Network interface ID is empty", svc1log.SafeParam("networkInterface", ni))
			errors = append(errors, "Network interface ID is empty")
			continue
		}

		// Prepare status
		var status *string
		if ni.Status != "" {
			statusStr := string(ni.Status)
			status = &statusStr
		}

		// Prepare subnet IDs if available
		var subnetIds []string
		if aws.ToString(ni.SubnetId) != "" {
			subnetIds = []string{*ni.SubnetId}
		}

		// Create VPC reference
		var vpcReference *common.VpcReference
		if aws.ToString(ni.VpcId) != "" {
			vpcReference = &common.VpcReference{
				Id:        *ni.VpcId,
				Region:    region,
				SubnetIds: subnetIds,
			}
		} else {
			errors = append(errors, fmt.Sprintf("Network interface %s has no VPC ID", *ni.NetworkInterfaceId))
		}

		// Create network interface with nested structure
		privateIPAddresses := make([]*ec2.InstancePrivateIpAddress, 0, len(ni.PrivateIpAddresses))
		for _, privateIP := range ni.PrivateIpAddresses {
			if aws.ToString(privateIP.PrivateIpAddress) == "" {
				errors = append(errors, fmt.Sprintf("Network interface %s has a private IP assignment without an address", *ni.NetworkInterfaceId))
				continue
			}
			converted := &ec2.InstancePrivateIpAddress{
				PrivateIpAddress: *privateIP.PrivateIpAddress,
				Primary:          privateIP.Primary,
				PrivateDnsName:   privateIP.PrivateDnsName,
			}
			if privateIP.Association != nil {
				converted.PublicIpAddress = privateIP.Association.PublicIp
				converted.PublicDnsName = privateIP.Association.PublicDnsName
				converted.PublicIpOwnerId = privateIP.Association.IpOwnerId
			}
			privateIPAddresses = append(privateIPAddresses, converted)
		}

		fernNI := &ec2.InstanceNetworkInterface{
			Identification: &ec2.InstanceNetworkInterfaceIdentificationInfo{
				Id:     *ni.NetworkInterfaceId,
				Region: region,
			},
			Configuration: &ec2.InstanceNetworkInterfaceConfigurationInfo{
				Description:        ni.Description,
				OwnerId:            ni.OwnerId,
				Status:             status,
				MacAddress:         ni.MacAddress,
				PrivateIpAddress:   ni.PrivateIpAddress,
				PrivateDnsName:     ni.PrivateDnsName,
				PrivateIpAddresses: privateIPAddresses,
				SourceDestCheck:    ni.SourceDestCheck,
			},
		}
		if vpcReference != nil {
			fernNI.Resources = &ec2.InstanceNetworkInterfaceResourceInfo{Vpc: vpcReference}
		}

		fernInterfaces = append(fernInterfaces, fernNI)
	}

	return fernInterfaces, errors
}

// convertTags converts AWS tags to Fern format
func convertTags(tags []types.Tag) []*ec2.Tag {
	var fernTags []*ec2.Tag

	for _, tag := range tags {
		fernTag := &ec2.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		}
		fernTags = append(fernTags, fernTag)
	}

	return fernTags
}

// extractNameFromTags extracts the name from EC2 tags
func extractNameFromTags(tags []types.Tag) *string {
	for _, tag := range tags {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			return tag.Value
		}
	}
	return nil
}

// extractSecurityGroupIds extracts security group IDs from AWS security groups
func extractSecurityGroupIds(securityGroups []types.GroupIdentifier) []string {
	var securityGroupIds []string

	for _, sg := range securityGroups {
		if aws.ToString(sg.GroupId) != "" {
			securityGroupIds = append(securityGroupIds, *sg.GroupId)
		}
	}

	return securityGroupIds
}

package securitygroup

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/methodaws/generated/go/common"
	fernsecuritygroup "github.com/Method-Security/methodaws/generated/go/securitygroup"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// fetchSecurityGroupRules retrieves detailed rules for a specific security group
func fetchSecurityGroupRules(ctx context.Context, cfg aws.Config, groupID string) ([]ec2types.SecurityGroupRule, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeSecurityGroupRulesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{groupID},
			},
		},
	}

	var allRules []ec2types.SecurityGroupRule
	paginator := ec2.NewDescribeSecurityGroupRulesPaginator(svc, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return allRules, err
		}
		if output == nil {
			return allRules, fmt.Errorf("DescribeSecurityGroupRules returned no response for security group %s", groupID)
		}
		allRules = append(allRules, output.SecurityGroupRules...)
	}

	return allRules, nil
}

// EnumerateSecurityGroups lists all of the security groups available to the caller across multiple regions
// alongside any non-fatal errors that occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// This includes both EC2/VPC security groups and RDS DB security groups.
// If vpcID is not nil, it will only return EC2 security groups associated with that VPC.
func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, config fernsecuritygroup.SecurityGroupsEnumerateConfig) *fernsecuritygroup.SecurityGroupsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting SecurityGroup enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)))

	report := fernsecuritygroup.SecurityGroupsEnumerateReport{
		Config: &config,
		Result: &fernsecuritygroup.SecurityGroupsEnumerateResult{},
	}

	var allSecurityGroups []*fernsecuritygroup.SecurityGroup
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing SecurityGroups in region", svc1log.SafeParam("region", region))

		// Enumerate EC2 security groups
		ec2SecurityGroups, ec2Errors := enumerateEC2SecurityGroupForRegion(ctx, cfg, region)

		// Enumerate RDS DB security groups
		rdsSecurityGroups, rdsErrors := enumerateRDSSecurityGroupForRegion(ctx, cfg, region)

		totalErrors := append(ec2Errors, rdsErrors...)
		if len(totalErrors) > 0 {
			log.Warn("Errors occurred while enumerating SecurityGroups in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(totalErrors)))
		}

		// Convert AWS SDK EC2 SecurityGroups to Fern SecurityGroups
		for _, sg := range ec2SecurityGroups {
			if sg.GroupId == nil {
				log.Warn("EC2 SecurityGroup ID is nil", svc1log.SafeParam("sg", sg))
				allErrors = append(allErrors, "EC2 SecurityGroup ID is nil")
				continue
			}
			fernSG, errors := convertAWSEC2SecurityGroupToFern(ctx, cfg, sg, region)
			allErrors = append(allErrors, errors...)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}

		// Convert AWS SDK RDS DB SecurityGroups to Fern SecurityGroups
		for _, sg := range rdsSecurityGroups {
			if sg.DBSecurityGroupName == nil {
				log.Warn("RDS DB SecurityGroup Name is nil", svc1log.SafeParam("sg", sg))
				allErrors = append(allErrors, "RDS DB SecurityGroup Name is nil")
				continue
			}
			fernSG := convertAWSRDSSecurityGroupToFern(sg, region)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}

		log.Info("Successfully processed SecurityGroups in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("ec2SecurityGroupCount", len(ec2SecurityGroups)),
			svc1log.SafeParam("rdsSecurityGroupCount", len(rdsSecurityGroups)))

		allErrors = append(allErrors, totalErrors...)
	}

	if len(allSecurityGroups) > 0 {
		report.Result.SecurityGroups = allSecurityGroups
	}
	report.Errors = allErrors
	return &report
}

// enumerateEC2SecurityGroupForRegion lists all of the EC2 security groups available to the caller for a specific region.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func enumerateEC2SecurityGroupForRegion(ctx context.Context, cfg aws.Config, region string) ([]ec2types.SecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating EC2 SecurityGroups for region",
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("vpcId", nil))

	cfg.Region = region
	svc := ec2.NewFromConfig(cfg)
	var securityGroups []ec2types.SecurityGroup
	var errors []string

	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve EC2 SecurityGroups page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}

	if len(securityGroups) > 0 {
		log.Info("Successfully enumerated EC2 SecurityGroups",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))
	} else {
		log.Info("No EC2 SecurityGroups found in region", svc1log.SafeParam("region", region))
	}
	return securityGroups, errors
}

// enumerateRDSSecurityGroupForRegion lists all of the RDS DB security groups available to the caller for a specific region.
// Note: RDS DB security groups are mostly legacy for EC2-Classic which was retired August 15, 2022.
func enumerateRDSSecurityGroupForRegion(ctx context.Context, cfg aws.Config, region string) ([]rdstypes.DBSecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating RDS DB SecurityGroups for region",
		svc1log.SafeParam("region", region))

	cfg.Region = region
	svc := rds.NewFromConfig(cfg)
	var securityGroups []rdstypes.DBSecurityGroup
	var errors []string

	paginator := rds.NewDescribeDBSecurityGroupsPaginator(svc, &rds.DescribeDBSecurityGroupsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve RDS DB SecurityGroups page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.DBSecurityGroups...)
	}

	if len(securityGroups) > 0 {
		log.Info("Successfully enumerated RDS DB SecurityGroups",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))
	} else {
		log.Info("No RDS DB SecurityGroups found in region", svc1log.SafeParam("region", region))
	}
	return securityGroups, errors
}

// convertAWSEC2SecurityGroupToFern converts an AWS SDK EC2 SecurityGroup to a Fern SecurityGroup
func convertAWSEC2SecurityGroupToFern(ctx context.Context, cfg aws.Config, awsSG ec2types.SecurityGroup, region string) (*fernsecuritygroup.SecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	var errors []string
	if awsSG.GroupId == nil {
		return nil, []string{"EC2 security group ID is missing"}
	}

	// Fetch detailed security group rules to get rule IDs
	var detailedRules []ec2types.SecurityGroupRule
	cfg.Region = region
	rules, err := fetchSecurityGroupRules(ctx, cfg, *awsSG.GroupId)
	detailedRules = rules
	if err != nil {
		log.Warn("Failed to fetch detailed security group rules",
			svc1log.SafeParam("groupId", *awsSG.GroupId),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("failed to fetch detailed rules for security group %s: %v", *awsSG.GroupId, err))
	}

	// Convert SecurityGroupRules directly to fernsecuritygroup.IpPermission
	var fernPermissions []*fernsecuritygroup.RuleDetails
	for _, rule := range detailedRules {
		fernPerm, err := convertAWSEC2SecurityGroupRuleToFern(rule)
		if err != nil {
			log.Warn("Failed to convert SecurityGroupRule", svc1log.SafeParam("rule", rule), svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			continue
		}
		fernPermissions = append(fernPermissions, fernPerm)
	}

	// Convert Tags
	var fernTags []*common.Tag
	if awsSG.Tags != nil {
		for _, tag := range awsSG.Tags {
			fernTag := &common.Tag{
				Key:   tag.Key,
				Value: tag.Value,
			}
			fernTags = append(fernTags, fernTag)
		}
	}

	// Create VPC reference if VPC ID exists
	var vpcReference *common.VpcReference
	if awsSG.VpcId != nil {
		vpcReference = &common.VpcReference{
			Id:     *awsSG.VpcId,
			Region: region,
		}
	}

	// Create the SecurityGroup with nested structure
	fernSG := &fernsecuritygroup.SecurityGroup{
		Identification: &fernsecuritygroup.SecurityGroupIdentificationInfo{
			Id:     *awsSG.GroupId,
			Region: region,
			Name:   awsSG.GroupName,
		},
		Configuration: &fernsecuritygroup.SecurityGroupConfigurationInfo{
			Description:       awsSG.Description,
			SecurityGroupType: fernsecuritygroup.SecurityGroupTypeEc2,
			OwnerId:           awsSG.OwnerId,
			Tags:              fernTags,
		},
	}

	// Add resources if we have VPC or permissions
	if vpcReference != nil || len(fernPermissions) > 0 {
		resourceInfo := &fernsecuritygroup.SecurityGroupResourceInfo{
			Vpc:   vpcReference,
			Rules: fernPermissions,
		}
		fernSG.Resources = resourceInfo
	}

	return fernSG, errors
}

func convertAWSEC2SecurityGroupRuleToFern(rule ec2types.SecurityGroupRule) (*fernsecuritygroup.RuleDetails, error) {
	if rule.SecurityGroupRuleId == nil {
		return nil, fmt.Errorf("SecurityGroupRule missing ID")
	}

	direction := fernsecuritygroup.PermissionDirectionIngress
	if rule.IsEgress != nil && *rule.IsEgress {
		direction = fernsecuritygroup.PermissionDirectionEgress
	}

	fernPerm := &fernsecuritygroup.RuleDetails{
		Identification: &fernsecuritygroup.RuleIdentificationInfo{Id: *rule.SecurityGroupRuleId},
		Configuration: &fernsecuritygroup.RuleConfigurationInfo{
			Direction:  direction,
			IpProtocol: rule.IpProtocol,
			Peer:       &fernsecuritygroup.RulePeerInfo{},
		},
	}

	if rule.FromPort != nil {
		fromPort := int(*rule.FromPort)
		fernPerm.Configuration.FromPort = &fromPort
	}
	if rule.ToPort != nil {
		toPort := int(*rule.ToPort)
		fernPerm.Configuration.ToPort = &toPort
	}
	fernPerm.Configuration.Description = rule.Description

	var cidrs []string
	if rule.CidrIpv4 != nil {
		cidrs = append(cidrs, *rule.CidrIpv4)
	}
	if rule.CidrIpv6 != nil {
		cidrs = append(cidrs, *rule.CidrIpv6)
	}
	fernPerm.Configuration.Peer.Cidrs = cidrs

	if rule.ReferencedGroupInfo != nil && rule.ReferencedGroupInfo.GroupId != nil {
		fernPerm.Configuration.Peer.ReferencedSecurityGroup = &fernsecuritygroup.ReferencedSecurityGroup{
			GroupId: *rule.ReferencedGroupInfo.GroupId,
			UserId:  rule.ReferencedGroupInfo.UserId,
		}
	}
	fernPerm.Configuration.Peer.PrefixListId = rule.PrefixListId

	if len(cidrs) == 0 && fernPerm.Configuration.Peer.ReferencedSecurityGroup == nil && rule.PrefixListId == nil {
		return nil, fmt.Errorf("SecurityGroupRule %s missing peer", *rule.SecurityGroupRuleId)
	}
	return fernPerm, nil
}

// convertAWSRDSSecurityGroupToFern converts an AWS SDK RDS DB SecurityGroup to a Fern SecurityGroup
func convertAWSRDSSecurityGroupToFern(awsSG rdstypes.DBSecurityGroup, region string) *fernsecuritygroup.SecurityGroup {
	// Create VPC reference if VPC ID exists
	var vpcReference *common.VpcReference
	if awsSG.VpcId != nil {
		vpcReference = &common.VpcReference{
			Id:     *awsSG.VpcId,
			Region: region,
		}
	}

	// Create the SecurityGroup with nested structure
	fernSG := &fernsecuritygroup.SecurityGroup{
		Identification: &fernsecuritygroup.SecurityGroupIdentificationInfo{
			Id:     *awsSG.DBSecurityGroupName,
			Arn:    awsSG.DBSecurityGroupArn,
			Name:   awsSG.DBSecurityGroupName,
			Region: region,
		},
		Configuration: &fernsecuritygroup.SecurityGroupConfigurationInfo{
			Description:       awsSG.DBSecurityGroupDescription,
			SecurityGroupType: fernsecuritygroup.SecurityGroupTypeRds,
			OwnerId:           awsSG.OwnerId,
		},
	}

	// Add resources if we have VPC
	if vpcReference != nil {
		resourceInfo := &fernsecuritygroup.SecurityGroupResourceInfo{
			Vpc:   vpcReference,
			Rules: nil, // RDS DB security group rules are not mapped in the unified schema
		}
		fernSG.Resources = resourceInfo
	}

	// Note: EC2SecurityGroups and IPRanges are not included in the Fern SecurityGroup definition
	// These fields exist in the RDS DB SecurityGroup but are not mapped to the unified SecurityGroup schema

	return fernSG
}

// Package rds provides functionality to enumerate and integrate AWS RDS resources.
package rds

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/methodaws/generated/go/common"
	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateRDS(ctx context.Context, awsConfig aws.Config, config rdsfern.RdsEnumerateConfig) *rdsfern.RdsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDS enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &rdsfern.RdsEnumerateReport{
		Config: &config,
		Result: &rdsfern.RdsEnumerateResult{},
	}

	var allRDSInstances []*rdsfern.RdsInstance
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing RDS instances in region", svc1log.SafeParam("region", region))
		instances, errors := enumerateRDSForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating RDS instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allRDSInstances = append(allRDSInstances, instances...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed RDS instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("instanceCount", len(instances)))
	}

	// Marshal report
	if len(allRDSInstances) > 0 {
		report.Result.RdsInstances = allRDSInstances
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed RDS enumeration",
		svc1log.SafeParam("totalInstances", len(allRDSInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

func enumerateRDSForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*rdsfern.RdsInstance, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	rdsClient := rds.NewFromConfig(awsConfig)
	var errors []string

	// List RDS instances
	instances, listErrors := listRDSInstances(ctx, rdsClient)
	if len(listErrors) > 0 {
		for _, e := range listErrors {
			errorMsg := "Failed to list RDS instances in region " + region + ": " + e
			log.Warn("Error listing RDS instances", svc1log.SafeParam("error", e))
			errors = append(errors, errorMsg)
		}
	}

	log.Info("Successfully listed RDS instances", svc1log.SafeParam("count", len(instances)))

	var rdsInstances []*rdsfern.RdsInstance
	for _, instance := range instances {
		rdsInstance, errs := convertAWSDBInstanceToFern(instance, region)
		if rdsInstance != nil {
			rdsInstances = append(rdsInstances, rdsInstance)
		}
		for _, err := range errs {
			errors = append(errors, fmt.Sprintf("RDS instance %q (%s) in region %s: %s", aws.ToString(instance.DBInstanceIdentifier), aws.ToString(instance.DBInstanceArn), region, err))
		}
	}

	return rdsInstances, errors
}

func listRDSInstances(ctx context.Context, rdsClient *rds.Client) ([]types.DBInstance, []string) {
	var instances []types.DBInstance
	var errors []string
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, err.Error())
			break
		}

		instances = append(instances, page.DBInstances...)
	}

	return instances, errors
}

// convertAWSDBInstanceToFern converts an AWS RDS DB Instance to a Fern RDS Instance
func convertAWSDBInstanceToFern(instance types.DBInstance, region string) (*rdsfern.RdsInstance, []string) {
	errors := []string{}

	// DescribeDBInstances also returns these non-RDS services.
	if aws.ToString(instance.Engine) == "docdb" || aws.ToString(instance.Engine) == "neptune" {
		return nil, nil
	}

	// Core Identity & Status (required field)
	if aws.ToString(instance.DBInstanceIdentifier) == "" || aws.ToString(instance.DBInstanceArn) == "" || region == "" {
		return nil, []string{"RDS DB instance identifier, ARN, or region is missing"}
	}
	instanceARN, err := arn.Parse(*instance.DBInstanceArn)
	if err != nil || instanceARN.Partition == "" || instanceARN.AccountID == "" || instanceARN.Service != "rds" ||
		instanceARN.Region != region || instanceARN.Resource != "db:"+*instance.DBInstanceIdentifier {
		return nil, []string{fmt.Sprintf("invalid or mismatched RDS DB instance ARN %q", *instance.DBInstanceArn)}
	}
	dbInstance := &rdsfern.RdsInstance{
		Identification: &rdsfern.RdsIdentificationInfo{
			Arn:    *instance.DBInstanceArn,
			Id:     *instance.DBInstanceIdentifier,
			Name:   instance.DBInstanceIdentifier,
			Region: region,
		},
		Configuration: &rdsfern.RdsConfigurationInfo{
			Status:             instance.DBInstanceStatus,
			Class:              instance.DBInstanceClass,
			Engine:             instance.Engine,
			EngineVersion:      instance.EngineVersion,
			DatabaseName:       instance.DBName,
			MasterUsername:     instance.MasterUsername,
			AvailabilityZone:   instance.AvailabilityZone,
			MultiAz:            instance.MultiAZ,
			PubliclyAccessible: instance.PubliclyAccessible,
		},
		Resources: &rdsfern.RdsResourceInfo{},
	}

	// Network & Availability
	if instance.Endpoint != nil {
		if aws.ToString(instance.Endpoint.Address) == "" || instance.Endpoint.Port == nil || *instance.Endpoint.Port < 1 || *instance.Endpoint.Port > 65535 {
			errors = append(errors, "DB endpoint is missing its address or a valid port")
		} else {
			dbInstance.Configuration.Endpoint = &rdsfern.Endpoint{
				Address:      *instance.Endpoint.Address,
				Port:         int(*instance.Endpoint.Port),
				HostedZoneId: instance.Endpoint.HostedZoneId,
			}
		}
	}

	// VPC References (minimal VPC info to avoid duplication with VPC enumeration)
	if instance.DBSubnetGroup != nil {
		var subnetIds []string
		for _, subnet := range instance.DBSubnetGroup.Subnets {
			if aws.ToString(subnet.SubnetIdentifier) != "" {
				subnetIds = append(subnetIds, *subnet.SubnetIdentifier)
			} else {
				errors = append(errors, "DB subnet group has a subnet without an ID")
			}
		}
		dbInstance.Configuration.DbSubnetGroupSubnetIds = subnetIds

		if aws.ToString(instance.DBSubnetGroup.VpcId) != "" {
			dbInstance.Resources.Vpc = &common.VpcReference{
				Id:     *instance.DBSubnetGroup.VpcId,
				Region: region,
			}
		} else {
			errors = append(errors, "DB subnet group is missing its VPC ID")
		}
	}

	// Storage Configuration
	var allocatedStorage, maxStorage, storageThroughput, iops *int
	if instance.AllocatedStorage != nil {
		val := int(*instance.AllocatedStorage)
		allocatedStorage = &val
	}
	if instance.MaxAllocatedStorage != nil {
		val := int(*instance.MaxAllocatedStorage)
		maxStorage = &val
	}
	if instance.StorageThroughput != nil {
		val := int(*instance.StorageThroughput)
		storageThroughput = &val
	}
	if instance.Iops != nil {
		val := int(*instance.Iops)
		iops = &val
	}
	dbInstance.Configuration.Storage = &rdsfern.StorageConfig{
		AllocatedStorage:    allocatedStorage,
		MaxAllocatedStorage: maxStorage,
		StorageType:         instance.StorageType,
		StorageEncrypted:    instance.StorageEncrypted,
		StorageThroughput:   storageThroughput,
		Iops:                iops,
	}

	// Security Configuration - create SecurityGroupReference objects
	var securityGroups []*common.SecurityGroupReference
	for _, sg := range instance.VpcSecurityGroups {
		if aws.ToString(sg.VpcSecurityGroupId) != "" {
			securityGroups = append(securityGroups, &common.SecurityGroupReference{
				Id:     *sg.VpcSecurityGroupId,
				Region: region,
			})
		} else {
			errors = append(errors, "VPC security group membership is missing its ID")
		}
	}
	dbInstance.Configuration.Security = &rdsfern.SecurityConfig{
		DeletionProtection:               instance.DeletionProtection,
		IamDatabaseAuthenticationEnabled: instance.IAMDatabaseAuthenticationEnabled,
		KmsKeyId:                         instance.KmsKeyId,
	}

	// Set security groups in Resources
	dbInstance.Resources.SecurityGroups = securityGroups

	// Monitoring Configuration
	var monitoringInterval *int
	if instance.MonitoringInterval != nil {
		val := int(*instance.MonitoringInterval)
		monitoringInterval = &val
	}
	dbInstance.Configuration.Monitoring = &rdsfern.MonitoringConfig{
		MonitoringInterval:          monitoringInterval,
		MonitoringRoleArn:           instance.MonitoringRoleArn,
		PerformanceInsightsEnabled:  instance.PerformanceInsightsEnabled,
		PerformanceInsightsKmsKeyId: instance.PerformanceInsightsKMSKeyId,
	}

	// Backup Configuration
	var backupRetention *int
	if instance.BackupRetentionPeriod != nil {
		val := int(*instance.BackupRetentionPeriod)
		backupRetention = &val
	}

	dbInstance.Configuration.Backup = &rdsfern.BackupConfig{
		BackupRetentionPeriod:      backupRetention,
		PreferredBackupWindow:      instance.PreferredBackupWindow,
		PreferredMaintenanceWindow: instance.PreferredMaintenanceWindow,
		CopyTagsToSnapshot:         instance.CopyTagsToSnapshot,
		LatestRestorableTime:       instance.LatestRestorableTime,
	}

	// Metadata
	dbInstance.Configuration.InstanceCreateTime = instance.InstanceCreateTime

	// Tags
	var tags []*common.Tag
	for _, tag := range instance.TagList {
		tags = append(tags, &common.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		})
	}
	dbInstance.Configuration.Tags = tags

	return dbInstance, errors
}

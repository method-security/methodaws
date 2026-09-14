// Package rds provides functionality to enumerate and integrate AWS RDS resources.
package rds

import (
	// Standard
	"context"
	// Generated
	common "github.com/Method-Security/methodaws/generated/go/common"
	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
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
		// Check for required DBInstanceIdentifier
		if instance.DBInstanceArn == nil {
			log.Warn("RDS DB Instance ARN is nil", svc1log.SafeParam("instance", instance))
			errors = append(errors, "RDS DB Instance ARN is nil")
			continue
		}

		rdsInstance, errs := convertAWSDBInstanceToFern(instance, region)
		if rdsInstance != nil {
			rdsInstances = append(rdsInstances, rdsInstance)
		}
		errors = append(errors, errs...)
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

	// Core Identity & Status (required field)
	if instance.DBInstanceIdentifier == nil || instance.DBInstanceArn == nil {
		return nil, []string{"RDS DB instance identifier or ARN is missing"}
	}
	dbInstance := &rdsfern.RdsInstance{
		Identification: &rdsfern.RdsIdentificationInfo{
			Arn:    *instance.DBInstanceArn,
			Id:     instance.DBInstanceIdentifier,
			Name:   instance.DBName,
			Region: region,
		},
		Configuration: &rdsfern.RdsConfigurationInfo{
			Status:             instance.DBInstanceStatus,
			Class:              instance.DBInstanceClass,
			Engine:             instance.Engine,
			EngineVersion:      instance.EngineVersion,
			MasterUsername:     instance.MasterUsername,
			AvailabilityZone:   instance.AvailabilityZone,
			MultiAz:            instance.MultiAZ,
			PubliclyAccessible: instance.PubliclyAccessible,
		},
		Resources: &rdsfern.RdsResourceInfo{},
	}

	// Network & Availability
	if instance.Endpoint != nil {
		var port *int
		if instance.Endpoint.Port != nil {
			val := int(*instance.Endpoint.Port)
			port = &val
		}
		dbInstance.Configuration.Endpoint = &rdsfern.Endpoint{
			Address:      instance.Endpoint.Address,
			Port:         port,
			HostedZoneId: instance.Endpoint.HostedZoneId,
		}
	}

	// VPC References (minimal VPC info to avoid duplication with VPC enumeration)
	if instance.DBSubnetGroup != nil && instance.DBSubnetGroup.VpcId != nil {
		// Get subnet IDs from the subnet group
		var subnetIds []string
		for _, subnet := range instance.DBSubnetGroup.Subnets {
			if subnet.SubnetIdentifier != nil {
				subnetIds = append(subnetIds, *subnet.SubnetIdentifier)
			}
		}

		if instance.DBSubnetGroup.VpcId != nil {
			dbInstance.Resources.Vpc = &common.VpcReference{
				Id:        *instance.DBSubnetGroup.VpcId,
				Region:    region,
				SubnetIds: subnetIds,
			}
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
		if sg.VpcSecurityGroupId != nil {
			securityGroups = append(securityGroups, &common.SecurityGroupReference{
				Id:     *sg.VpcSecurityGroupId,
				Region: region,
			})
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

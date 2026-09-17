package enumerate

import (
	"context"
	"fmt"

	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2aws "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamaws "github.com/aws/aws-sdk-go-v2/service/iam"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// InternalEnumerateEc2 enumerates ec2aws resources based on the provided configuration
func InternalEnumerateEc2(ctx context.Context, awsConfig aws.Config, config ec2.Ec2EnumerateConfig) *ec2.Ec2EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting ec2aws enumeration",
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Initialize report
	report := &ec2.Ec2EnumerateReport{
		Config: &config,
		Result: &ec2.Ec2EnumerateResult{},
	}

	var allInstances []*ec2.Ec2Instance
	var allErrors []string
	profileCache := make(instanceProfileCache)

	// Enumerate instances across all regions
	for _, region := range config.Regions {
		log.Info("Enumerating ec2 instances for region", svc1log.SafeParam("region", region))
		instances, errs := enumerateEc2ForRegion(ctx, awsConfig, region, profileCache)

		if len(instances) > 0 {
			allInstances = append(allInstances, instances...)
		}
		if len(errs) > 0 {
			allErrors = append(allErrors, errs...)
		}
	}

	// Populate report
	if len(allInstances) > 0 {
		report.Result.Instances = allInstances
		log.Info("Successfully enumerated ec2 instances",
			svc1log.SafeParam("totalInstances", len(allInstances)))
	} else {
		log.Info("No ec2 instances found across all regions")
		report.Result.Instances = []*ec2.Ec2Instance{}
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
		log.Warn("Errors encountered during ec2 enumeration",
			svc1log.SafeParam("errorCount", len(allErrors)))
	}

	log.Info("Completed ec2 enumeration",
		svc1log.SafeParam("totalInstances", len(allInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// enumerateEc2ForRegion retrieves all ec2 instances for a specific region
func enumerateEc2ForRegion(ctx context.Context, awsConfig aws.Config, region string, profileCache instanceProfileCache) ([]*ec2.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	var instances []*ec2.Ec2Instance
	var errors []string

	// Create region-specific config and client
	regionConfig := awsConfig.Copy()
	regionConfig.Region = region
	client := ec2aws.NewFromConfig(regionConfig)
	iamClient := iamaws.NewFromConfig(regionConfig)

	// Get all instances
	reservations, errs := getAllReservations(ctx, client, region)
	errors = append(errors, errs...)

	log.Info("Processing ec2aws instances",
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("reservationCount", len(reservations)))

	// Process each instance
	for _, reservation := range reservations {
		for _, awsInstance := range reservation.Instances {
			instance, errs := processInstance(ctx, awsInstance, region, aws.ToString(reservation.OwnerId))
			if instance != nil {
				role, err := profileCache.resolveRole(ctx, iamClient, awsInstance.IamInstanceProfile)
				if err != nil {
					errs = append(errs, err.Error())
				}
				instance.Resources.IamRole = role
				instances = append(instances, instance)
			}
			for _, err := range errs {
				errors = append(errors, fmt.Sprintf("Instance %s in region %s: %s", aws.ToString(awsInstance.InstanceId), region, err))
			}
		}
	}

	return instances, errors
}

// getAllReservations preserves the owner account for each returned instance.
func getAllReservations(ctx context.Context, client *ec2aws.Client, region string) ([]types.Reservation, []string) {
	var reservations []types.Reservation
	var errors []string

	paginator := ec2aws.NewDescribeInstancesPaginator(client, &ec2aws.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to list instances in region %s: %s", region, err.Error()))
			break
		}

		reservations = append(reservations, result.Reservations...)
	}

	return reservations, errors
}

// processInstance converts an AWS instance to Fern format
func processInstance(ctx context.Context, awsInstance types.Instance, region, ownerID string) (*ec2.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Processing ec2aws instance", svc1log.SafeParam("instanceId", awsInstance.InstanceId))
	// Child conversion errors must not discard an identified instance.
	return convertInstanceToFern(ctx, awsInstance, region, ownerID)
}

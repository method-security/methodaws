package enumerate

import (
	// Standard
	"context"
	"fmt"

	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func GatherCloudFrontInfo(ctx context.Context, awsConfig aws.Config, config cloudfrontfern.CloudFrontEnumerateConfig) *cloudfrontfern.CloudFrontEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting CloudFront enumeration (global service)",
		svc1log.SafeParam("accountID", config.AccountId))

	// Initialize report
	report := &cloudfrontfern.CloudFrontEnumerateReport{
		Config: &config,
		Result: &cloudfrontfern.CloudFrontEnumerateResult{},
	}

	// CloudFront is a global service, always use us-east-1
	distributions, errors := enumerateCloudFrontDistributions(ctx, awsConfig, config)

	if len(errors) > 0 {
		log.Warn("Errors occurred while enumerating CloudFront distributions",
			svc1log.SafeParam("errorCount", len(errors)))
		report.Errors = errors
	}

	if len(distributions) > 0 {
		report.Result.Distributions = distributions
	}

	log.Info("Completed CloudFront enumeration",
		svc1log.SafeParam("totalDistributions", len(distributions)),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}

func enumerateCloudFrontDistributions(ctx context.Context, awsConfig aws.Config, config cloudfrontfern.CloudFrontEnumerateConfig) ([]*cloudfrontfern.CloudFrontDistribution, []string) {
	log := svc1log.FromContext(ctx)
	// CloudFront is a global service, always use us-east-1
	awsConfig.Region = "us-east-1"

	cloudfrontClient := cloudfront.NewFromConfig(awsConfig)
	var errors []string

	log.Info("Listing CloudFront distributions from global endpoint")

	// List CloudFront distributions
	distributions, err := listCloudFrontDistributions(ctx, cloudfrontClient)
	if err != nil {
		errorMsg := "Failed to list CloudFront distributions: " + err.Error()
		log.Error("Error listing CloudFront distributions", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, errorMsg)
		return nil, errors
	}

	log.Info("Successfully listed CloudFront distributions", svc1log.SafeParam("count", len(distributions)))

	var cloudFrontDistributions []*cloudfrontfern.CloudFrontDistribution
	for _, dist := range distributions {
		if dist.ARN == nil || dist.Id == nil {
			log.Warn("Distribution identity is incomplete", svc1log.SafeParam("distribution", dist))
			errors = append(errors, "Distribution ARN or ID is nil")
			continue
		}
		distribution, errs := processDistribution(ctx, awsConfig, cloudfrontClient, dist, config.AccountId)
		if len(errs) > 0 {
			log.Error("Error processing distribution, using fallback transformation",
				svc1log.SafeParam("distributionId", *dist.Id))
			errors = append(errors, errs...)
			// Use fallback transformation when full distribution processing fails
			var fallbackErrs []string
			distribution, fallbackErrs = transformDistributionSummaryToFern(ctx, awsConfig, dist, config.AccountId)
			errors = append(errors, fallbackErrs...)
		}
		cloudFrontDistributions = append(cloudFrontDistributions, distribution)
	}

	return cloudFrontDistributions, errors
}

// processDistribution gets full distribution details and transforms them to Fern format
func processDistribution(ctx context.Context, awsConfig aws.Config, cloudfrontClient *cloudfront.Client, distSummary types.DistributionSummary, accountID string) (*cloudfrontfern.CloudFrontDistribution, []string) {
	var errors []string
	// Get full distribution details
	fullDistribution, err := getDistributionDetails(ctx, cloudfrontClient, distSummary.Id)
	if err != nil {
		errors = append(errors, err.Error())
		return nil, errors
	}
	if fullDistribution == nil || fullDistribution.ARN == nil {
		return nil, []string{"GetDistribution returned an incomplete distribution"}
	}

	// Transform to Fern format
	distribution, errors := transformDistributionToFern(ctx, awsConfig, *fullDistribution, accountID)
	return distribution, errors
}

func listCloudFrontDistributions(ctx context.Context, cloudfrontClient *cloudfront.Client) ([]types.DistributionSummary, error) {
	var distributions []types.DistributionSummary
	paginator := cloudfront.NewListDistributionsPaginator(cloudfrontClient, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if page.DistributionList != nil {
			distributions = append(distributions, page.DistributionList.Items...)
		}
	}

	return distributions, nil
}

func getDistributionDetails(ctx context.Context, cloudfrontClient *cloudfront.Client, distributionID *string) (*types.Distribution, error) {
	input := &cloudfront.GetDistributionInput{
		Id: distributionID,
	}

	result, err := cloudfrontClient.GetDistribution(ctx, input)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("GetDistribution returned no response")
	}

	return result.Distribution, nil
}

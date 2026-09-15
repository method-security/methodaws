package enumerate

import (
	// Standard
	"context"
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// extractDistributionComment safely extracts comment from distribution config
func extractDistributionComment(comment *string) *string {
	if comment != nil && len(*comment) > 0 {
		return comment
	}
	return nil
}

// extractDistributionStatus determines the distribution status
func extractDistributionStatus(enabled bool) cloudfrontfern.CloudFrontDistributionStatus {
	if !enabled {
		return cloudfrontfern.CloudFrontDistributionStatusDisabled
	}
	return cloudfrontfern.CloudFrontDistributionStatusEnabled
}

func transformDistributionToFern(ctx context.Context, awsConfig aws.Config, dist types.Distribution, accountID string) (*cloudfrontfern.CloudFrontDistribution, []string) {
	if dist.ARN == nil {
		return nil, []string{"Distribution ARN is nil"}
	}
	if dist.DistributionConfig == nil {
		return nil, []string{"Distribution configuration is nil"}
	}
	if dist.DistributionConfig.Enabled == nil {
		return nil, []string{"Distribution Enabled is nil"}
	}
	var errors []string
	// Transform origins with enhanced details
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.DistributionConfig.Origins != nil {
		origins, errors = processOrigins(ctx, awsConfig, dist.DistributionConfig.Origins.Items, accountID)
	}

	// Extract comment and status using helper functions
	comment := extractDistributionComment(dist.DistributionConfig.Comment)
	status := extractDistributionStatus(*dist.DistributionConfig.Enabled)

	// Create distribution with nested structure
	return &cloudfrontfern.CloudFrontDistribution{
		Identification: &cloudfrontfern.CloudFrontDistributionIdentificationInfo{
			Arn:        *dist.ARN,
			Id:         dist.Id,
			DomainName: dist.DomainName,
		},
		Configuration: &cloudfrontfern.CloudFrontDistributionConfigurationInfo{
			Status:  status,
			Comment: comment,
		},
		Resources: &cloudfrontfern.CloudFrontDistributionResourceInfo{
			Origins: origins,
		},
	}, errors
}

// Fallback transformation for when we only have DistributionSummary
func transformDistributionSummaryToFern(ctx context.Context, awsConfig aws.Config, dist types.DistributionSummary, accountID string) (*cloudfrontfern.CloudFrontDistribution, []string) {
	if dist.ARN == nil {
		return nil, []string{"Distribution ARN is nil"}
	}
	if dist.Enabled == nil {
		return nil, []string{"Distribution Enabled is nil"}
	}
	var errors []string
	// Transform origins (limited info from summary)
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.Origins != nil {
		origins, errors = processOrigins(ctx, awsConfig, dist.Origins.Items, accountID)
	}

	// Extract comment and status using helper functions
	comment := extractDistributionComment(dist.Comment)
	status := extractDistributionStatus(*dist.Enabled)

	// Create distribution with nested structure
	return &cloudfrontfern.CloudFrontDistribution{
		Identification: &cloudfrontfern.CloudFrontDistributionIdentificationInfo{
			Arn:        *dist.ARN,
			Id:         dist.Id,
			DomainName: dist.DomainName,
		},
		Configuration: &cloudfrontfern.CloudFrontDistributionConfigurationInfo{
			Status:  status,
			Comment: comment,
		},
		Resources: &cloudfrontfern.CloudFrontDistributionResourceInfo{
			Origins: origins,
		},
	}, errors
}

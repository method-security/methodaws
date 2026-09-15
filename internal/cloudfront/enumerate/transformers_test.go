package enumerate

import (
	"context"
	"testing"

	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformDistributionRequiresEnabled(t *testing.T) {
	t.Parallel()

	distribution, errs := transformDistributionToFern(context.Background(), aws.Config{}, types.Distribution{
		ARN:                aws.String("arn:aws:cloudfront::123456789012:distribution/EXAMPLE"),
		DistributionConfig: &types.DistributionConfig{},
	}, "123456789012")

	assert.Nil(t, distribution)
	assert.Equal(t, []string{"Distribution Enabled is nil"}, errs)
}

func TestDistributionDomainNameOmitsPlaceholder(t *testing.T) {
	t.Parallel()
	for _, value := range []*string{nil, aws.String(""), aws.String(" - ")} {
		assert.Nil(t, distributionDomainName(value))
	}
	assert.Equal(t, aws.String("example.cloudfront.net"), distributionDomainName(aws.String("example.cloudfront.net")))
}

func TestTransformDistributionUsesExplicitEnabledStatus(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		enabled  bool
		expected cloudfrontfern.CloudFrontDistributionStatus
	}{
		{name: "enabled", enabled: true, expected: cloudfrontfern.CloudFrontDistributionStatusEnabled},
		{name: "disabled", enabled: false, expected: cloudfrontfern.CloudFrontDistributionStatusDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			distribution, errs := transformDistributionToFern(context.Background(), aws.Config{}, types.Distribution{
				ARN: aws.String("arn:aws:cloudfront::123456789012:distribution/EXAMPLE"),
				DistributionConfig: &types.DistributionConfig{
					Enabled: aws.Bool(test.enabled),
				},
			}, "123456789012")

			require.Empty(t, errs)
			require.NotNil(t, distribution)
			assert.Equal(t, test.expected, distribution.Configuration.Status)
		})
	}
}

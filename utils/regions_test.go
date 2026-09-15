package utils

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDescribeRegionsClient struct {
	output *ec2.DescribeRegionsOutput
	err    error
}

func (s stubDescribeRegionsClient) DescribeRegions(
	context.Context,
	*ec2.DescribeRegionsInput,
	...func(*ec2.Options),
) (*ec2.DescribeRegionsOutput, error) {
	return s.output, s.err
}

func TestEnabledAWSRegionsSortsDeduplicatesAndSkipsMissingNames(t *testing.T) {
	regions, err := enabledAWSRegions(context.Background(), stubDescribeRegionsClient{
		output: &ec2.DescribeRegionsOutput{Regions: []types.Region{
			{RegionName: aws.String("us-west-2")},
			{RegionName: nil},
			{RegionName: aws.String("us-east-1")},
			{RegionName: aws.String("us-west-2")},
		}},
	}, nil)

	require.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, regions)
}

func TestNormalizeSelectedRegions(t *testing.T) {
	regions, err := normalizeSelectedRegions([]string{"us-west-2", "mx-central-1", "us-west-2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"mx-central-1", "us-west-2"}, regions)

	_, err = normalizeSelectedRegions([]string{"us-east-1", "us-gov-west-1"})
	require.EqualError(t, err, "selected AWS regions must belong to one partition")

	_, err = normalizeSelectedRegions([]string{""})
	require.EqualError(t, err, "at least one AWS region must be selected")
}

func TestEnabledAWSRegionsValidatesSelectedRegions(t *testing.T) {
	client := stubDescribeRegionsClient{output: &ec2.DescribeRegionsOutput{Regions: []types.Region{
		{RegionName: aws.String("mx-central-1")},
		{RegionName: aws.String("us-west-2")},
	}}}

	regions, err := enabledAWSRegions(context.Background(), client, []string{"mx-central-1", "us-west-2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"mx-central-1", "us-west-2"}, regions)

	_, err = enabledAWSRegions(context.Background(), client, []string{"us-east-2"})
	require.EqualError(t, err, "AWS regions are not enabled or do not exist: us-east-2")
}

func TestRegionDiscoveryQueryRegionUsesStablePartitionEndpoint(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"mx-central-1":   "us-east-1",
		"us-eats-1":      "us-east-1",
		"cn-northwest-1": "cn-north-1",
		"us-gov-east-1":  "us-gov-west-1",
	}
	for selected, expected := range tests {
		actual, err := regionDiscoveryQueryRegion("", []string{selected})
		require.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestEnabledAWSRegionsHandlesMissingResponseAndErrors(t *testing.T) {
	_, err := enabledAWSRegions(context.Background(), stubDescribeRegionsClient{}, nil)
	require.EqualError(t, err, "describe enabled AWS regions returned no response")

	requestErr := errors.New("denied")
	_, err = enabledAWSRegions(context.Background(), stubDescribeRegionsClient{err: requestErr}, nil)
	require.EqualError(t, err, "describe enabled AWS regions: denied")
	var discoveryErr *describeRegionsRequestError
	require.ErrorAs(t, err, &discoveryErr)
	require.ErrorIs(t, err, requestErr)
}

func TestRegionDiscoveryFallback(t *testing.T) {
	t.Parallel()

	discoveryErr := errors.New("ec2:DescribeRegions denied")

	regions, err := regionDiscoveryFallback("", []string{"us-east-1", "us-west-2"}, discoveryErr)
	require.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, regions)

	regions, err = regionDiscoveryFallback("us-gov-west-1", nil, discoveryErr)
	require.NoError(t, err)
	assert.Equal(t, []string{"us-gov-west-1"}, regions)

	_, err = regionDiscoveryFallback("", nil, discoveryErr)
	require.ErrorIs(t, err, discoveryErr)
}

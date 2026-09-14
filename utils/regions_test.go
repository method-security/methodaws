package utils

import (
	"context"
	"errors"
	"sort"
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

func TestEnabledAWSRegionsValidatesSelectedRegions(t *testing.T) {
	client := stubDescribeRegionsClient{output: &ec2.DescribeRegionsOutput{Regions: []types.Region{
		{RegionName: aws.String("us-west-2")},
		{RegionName: aws.String("us-east-1")},
	}}}

	regions, err := enabledAWSRegions(context.Background(), client, []string{"us-west-2", "us-west-2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"us-west-2"}, regions)

	_, err = enabledAWSRegions(context.Background(), client, []string{"us-east-2"})
	require.EqualError(t, err, "AWS regions are not enabled or do not exist: us-east-2")
}

func TestEnabledAWSRegionsHandlesMissingResponseAndErrors(t *testing.T) {
	_, err := enabledAWSRegions(context.Background(), stubDescribeRegionsClient{}, nil)
	require.EqualError(t, err, "describe enabled AWS regions returned no response")

	_, err = enabledAWSRegions(context.Background(), stubDescribeRegionsClient{err: errors.New("denied")}, nil)
	require.EqualError(t, err, "describe enabled AWS regions: denied")
}

func TestGeneralRegionsAreSortedAndDeduplicated(t *testing.T) {
	regions := GetGeneralRegionsList()

	require.NotEmpty(t, regions)
	assert.True(t, sort.StringsAreSorted(regions))
	assert.Equal(t, len(regions), len(uniqueStrings(regions)))
}

func uniqueStrings(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

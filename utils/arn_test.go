package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRelatedARN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sourceARN string
		region    string
		resource  string
		expected  string
	}{
		{
			name:      "commercial partition",
			sourceARN: "arn:aws:lambda:us-east-1:123456789012:function:example",
			region:    "us-east-1",
			resource:  "log-group:/aws/lambda/example",
			expected:  "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/example",
		},
		{
			name:      "govcloud partition",
			sourceARN: "arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/example",
			region:    "us-gov-west-1",
			resource:  "log-group:/aws/eks/example/cluster",
			expected:  "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/eks/example/cluster",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual, err := BuildRelatedARN(test.sourceARN, "logs", test.region, test.resource)

			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestBuildRelatedARNRejectsUnusableSourceARN(t *testing.T) {
	t.Parallel()

	_, err := BuildRelatedARN("arn:aws:s3:::example", "logs", "us-east-1", "log-group:example")
	require.Error(t, err)
}

func TestBuildRegionalARNUsesRegionPartition(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"us-east-1":      "arn:aws:ec2:us-east-1:123456789012:instance/example",
		"mx-central-1":   "arn:aws:ec2:mx-central-1:123456789012:instance/example",
		"us-gov-west-1":  "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/example",
		"cn-north-1":     "arn:aws-cn:ec2:cn-north-1:123456789012:instance/example",
		"eusc-de-east-1": "arn:aws-eusc:ec2:eusc-de-east-1:123456789012:instance/example",
	}
	for region, expected := range tests {
		actual, err := BuildRegionalARN(region, "ec2", "123456789012", "instance/example")
		require.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestBuildGlobalARNForRegionOmitsARNRegion(t *testing.T) {
	t.Parallel()

	actual, err := BuildGlobalARNForRegion("us-gov-west-1", "s3", "", "example")
	require.NoError(t, err)
	assert.Equal(t, "arn:aws-us-gov:s3:::example", actual)
}

func TestBuildRegionalARNRejectsInvalidRegion(t *testing.T) {
	t.Parallel()

	_, err := BuildRegionalARN("not-a-region", "ec2", "123456789012", "instance/example")
	require.EqualError(t, err, `invalid AWS region "not-a-region"`)
}

func TestIsCommercialAWSRegion(t *testing.T) {
	t.Parallel()

	commercial, err := IsCommercialAWSRegion("mx-central-1")
	require.NoError(t, err)
	assert.True(t, commercial)

	commercial, err = IsCommercialAWSRegion("us-gov-west-1")
	require.NoError(t, err)
	assert.False(t, commercial)
}

func TestAWSDNSSuffixForRegion(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"us-east-1":      "amazonaws.com",
		"us-gov-west-1":  "amazonaws.com",
		"cn-north-1":     "amazonaws.com.cn",
		"eusc-de-east-1": "amazonaws.eu",
	}
	for region, expected := range tests {
		actual, err := AWSDNSSuffixForRegion(region)
		require.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

package lambda

import (
	"context"
	"errors"
	"testing"

	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	"github.com/Method-Security/methodaws/internal/networkreferences"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingNetworkReferenceClient struct{}

func (f *failingNetworkReferenceClient) DescribeVpcs(
	context.Context,
	*ec2.DescribeVpcsInput,
	...func(*ec2.Options),
) (*ec2.DescribeVpcsOutput, error) {
	return nil, errors.New("describe VPCs denied")
}

func (f *failingNetworkReferenceClient) DescribeSubnets(
	context.Context,
	*ec2.DescribeSubnetsInput,
	...func(*ec2.Options),
) (*ec2.DescribeSubnetsOutput, error) {
	return nil, errors.New("describe subnets denied")
}

func (f *failingNetworkReferenceClient) DescribeSecurityGroups(
	context.Context,
	*ec2.DescribeSecurityGroupsInput,
	...func(*ec2.Options),
) (*ec2.DescribeSecurityGroupsOutput, error) {
	return nil, errors.New("describe security groups denied")
}

func TestCreateCloudWatchLogReferencesUsesEffectiveLogGroupAndSourceIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		loggingConfig *lambdafern.LambdaLoggingConfig
		expectedName  string
	}{
		{
			name: "missing logging configuration",
		},
		{
			name: "configured default log group",
			loggingConfig: &lambdafern.LambdaLoggingConfig{
				LogGroup: "/aws/lambda/example",
			},
			expectedName: "/aws/lambda/example",
		},
		{
			name: "custom log group",
			loggingConfig: &lambdafern.LambdaLoggingConfig{
				LogGroup: "/method/lambda/example",
			},
			expectedName: "/method/lambda/example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			references, err := createCloudWatchLogReferences(
				test.loggingConfig,
				"arn:aws:lambda:us-east-1:123456789012:function:example",
				"us-east-1",
			)

			require.NoError(t, err)
			if test.expectedName == "" {
				assert.Empty(t, references)
				return
			}
			require.Len(t, references, 1)
			assert.Equal(t, test.expectedName, references[0].LogGroupName)
			assert.Equal(
				t,
				"arn:aws:logs:us-east-1:123456789012:log-group:"+test.expectedName,
				references[0].Arn,
			)
		})
	}
}

func TestVpcLookupFailureDoesNotReportMissingVpcID(t *testing.T) {
	t.Parallel()

	function, err := parseLambdaFunctionConfiguration(
		context.Background(),
		types.FunctionConfiguration{
			FunctionName: aws.String("example"),
			FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:example"),
			Role:         aws.String("arn:aws:iam::123456789012:role/example"),
			VpcConfig: &types.VpcConfigResponse{
				VpcId:            aws.String("vpc-aaaaaaaa"),
				SubnetIds:        []string{"subnet-aaaaaaaa"},
				SecurityGroupIds: []string{"sg-aaaaaaaa"},
			},
		},
		"us-east-1",
		networkreferences.New(&failingNetworkReferenceClient{}, "us-east-1"),
	)

	require.NotNil(t, function)
	require.Error(t, err)
	assert.ErrorContains(t, err, "describe VPCs denied")
	assert.NotContains(t, err.Error(), "no VPC ID")
}

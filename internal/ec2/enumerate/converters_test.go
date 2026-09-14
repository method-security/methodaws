package enumerate

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertInstanceDoesNotPromoteIdentifiersToARNs(t *testing.T) {
	t.Parallel()

	instance, errors := convertInstanceToFern(context.Background(), types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"),
		IamInstanceProfile: &types.IamInstanceProfile{
			Arn: aws.String("arn:aws:iam::123456789012:instance-profile/example"),
		},
		NetworkInterfaces: []types.InstanceNetworkInterface{
			{
				NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
				VpcId:              aws.String("vpc-0123456789abcdef0"),
			},
		},
	}, "us-east-1")

	require.Empty(t, errors)
	require.NotNil(t, instance)
	require.NotNil(t, instance.Resources)
	assert.Nil(t, instance.Resources.IamRole)
	require.Len(t, instance.Resources.NetworkInterfaces, 1)
	assert.Nil(t, instance.Resources.NetworkInterfaces[0].Identification.Arn)
}

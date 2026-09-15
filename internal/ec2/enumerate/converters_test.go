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

func TestConvertNetworkInterfacesIncludesEveryPrivateIPAddress(t *testing.T) {
	t.Parallel()

	interfaces, errs := convertNetworkInterfaces(context.Background(), []types.InstanceNetworkInterface{{
		NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
		VpcId:              aws.String("vpc-0123456789abcdef0"),
		PrivateIpAddresses: []types.InstancePrivateIpAddress{
			{PrivateIpAddress: aws.String("10.0.0.10"), Primary: aws.Bool(true)},
			{PrivateIpAddress: aws.String("10.0.0.11"), Primary: aws.Bool(false)},
		},
	}}, "us-east-1")

	require.Empty(t, errs)
	require.Len(t, interfaces, 1)
	require.Len(t, interfaces[0].Configuration.PrivateIpAddresses, 2)
	assert.Equal(t, "10.0.0.10", interfaces[0].Configuration.PrivateIpAddresses[0].PrivateIpAddress)
	assert.True(t, aws.ToBool(interfaces[0].Configuration.PrivateIpAddresses[0].Primary))
	assert.Equal(t, "10.0.0.11", interfaces[0].Configuration.PrivateIpAddresses[1].PrivateIpAddress)
}

func TestConvertInstanceTypePreservesAWSValue(t *testing.T) {
	t.Parallel()

	instanceType := types.InstanceType("m8g.48xlarge")

	assert.Equal(t, "m8g.48xlarge", aws.ToString(convertInstanceType(instanceType)))
	assert.Nil(t, convertInstanceType(""))
}

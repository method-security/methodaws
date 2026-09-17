package enumerate

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertInstanceUsesResourceOwnersForARNs(t *testing.T) {
	t.Parallel()

	instance, errors := convertInstanceToFern(context.Background(), types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"),
		IamInstanceProfile: &types.IamInstanceProfile{
			Arn: aws.String("arn:aws:iam::123456789012:instance-profile/example"),
		},
		NetworkInterfaces: []types.InstanceNetworkInterface{
			{
				NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
				OwnerId:            aws.String("210987654321"),
				VpcId:              aws.String("vpc-0123456789abcdef0"),
			},
		},
	}, "us-east-1", "123456789012")

	require.Empty(t, errors)
	require.NotNil(t, instance)
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", instance.Identification.Arn)
	assert.Equal(t, "i-0123456789abcdef0", instance.Identification.Id)
	require.NotNil(t, instance.Resources)
	assert.Nil(t, instance.Resources.IamRole)
	require.Len(t, instance.Resources.NetworkInterfaces, 1)
	assert.Equal(t, "arn:aws:ec2:us-east-1:210987654321:network-interface/eni-0123456789abcdef0", instance.Resources.NetworkInterfaces[0].Identification.Arn)
}

func TestConvertNetworkInterfacesIncludesEveryPrivateIPAddress(t *testing.T) {
	t.Parallel()

	interfaces, errs := convertNetworkInterfaces(context.Background(), []types.InstanceNetworkInterface{{
		NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
		OwnerId:            aws.String("123456789012"),
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

func TestInstanceARNPartitions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ region, partition string }{
		{"us-east-1", "aws"}, {"cn-north-1", "aws-cn"}, {"us-gov-west-1", "aws-us-gov"},
	} {
		t.Run(tc.region, func(t *testing.T) {
			instance, errs := convertInstanceToFern(context.Background(), types.Instance{
				InstanceId: aws.String("i-0123456789abcdef0"),
				NetworkInterfaces: []types.InstanceNetworkInterface{{
					NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
					OwnerId:            aws.String("123456789012"), VpcId: aws.String("vpc-0123456789abcdef0"),
				}},
			}, tc.region, "123456789012")
			require.Empty(t, errs)
			require.NotNil(t, instance)
			prefix := "arn:" + tc.partition + ":ec2:" + tc.region + ":123456789012:"
			assert.Equal(t, prefix+"instance/i-0123456789abcdef0", instance.Identification.Arn)
			assert.Equal(t, prefix+"network-interface/eni-0123456789abcdef0", instance.Resources.NetworkInterfaces[0].Identification.Arn)
		})
	}
}

func TestInvalidIdentityDoesNotEmitInstance(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ owner, region string }{
		{"", "us-east-1"}, {"invalid", "us-east-1"}, {"123456789012", ""}, {"123456789012", "invalid"},
	} {
		instance, errs := convertInstanceToFern(context.Background(), types.Instance{
			InstanceId: aws.String("i-0123456789abcdef0"),
		}, tc.region, tc.owner)
		assert.Nil(t, instance)
		assert.NotEmpty(t, errs)
	}
}

func TestInvalidInterfaceDoesNotDiscardInstanceOrOtherInterfaces(t *testing.T) {
	t.Parallel()
	instance, errs := convertInstanceToFern(context.Background(), types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"),
		NetworkInterfaces: []types.InstanceNetworkInterface{
			{NetworkInterfaceId: aws.String("eni-no-owner")},
			{
				NetworkInterfaceId: aws.String("eni-0123456789abcdef0"),
				OwnerId:            aws.String("123456789012"), VpcId: aws.String("vpc-0123456789abcdef0"),
				Groups: []types.GroupIdentifier{{GroupId: aws.String("sg-first")}, {}},
			},
			{
				NetworkInterfaceId: aws.String("eni-0123456789abcdef1"),
				OwnerId:            aws.String("123456789012"), VpcId: aws.String("vpc-0123456789abcdef0"),
				Groups: []types.GroupIdentifier{{GroupId: aws.String("sg-second")}},
			},
		},
	}, "us-east-1", "123456789012")
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "eni-no-owner")
	require.NotNil(t, instance)
	require.Len(t, instance.Resources.NetworkInterfaces, 2)
	assert.Equal(t, []string{"sg-first"}, instance.Resources.NetworkInterfaces[0].Resources.SecurityGroupIds)
	assert.Equal(t, []string{"sg-second"}, instance.Resources.NetworkInterfaces[1].Resources.SecurityGroupIds)
}

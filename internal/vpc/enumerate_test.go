package vpc

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertAWSSubnetPreservesPrivateDNSNameOptions(t *testing.T) {
	t.Parallel()

	subnet, errs := convertAWSSubnetToFern(types.Subnet{
		SubnetId: aws.String("subnet-0123456789abcdef0"),
		PrivateDnsNameOptionsOnLaunch: &types.PrivateDnsNameOptionsOnLaunch{
			HostnameType:                    types.HostnameTypeResourceName,
			EnableResourceNameDnsARecord:    aws.Bool(true),
			EnableResourceNameDnsAAAARecord: aws.Bool(false),
		},
	}, "us-east-1")

	require.Empty(t, errs)
	require.NotNil(t, subnet.Configuration.PrivateDnsNameOptionsOnLaunch)
	options := subnet.Configuration.PrivateDnsNameOptionsOnLaunch
	require.NotNil(t, options.HostnameType)
	assert.Equal(t, "resource-name", string(*options.HostnameType))
	assert.True(t, aws.ToBool(options.EnableResourceNameDnsARecord))
	assert.False(t, aws.ToBool(options.EnableResourceNameDnsAaaaRecord))
}

package securitygroup

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertEC2SecurityGroupRequiresID(t *testing.T) {
	securityGroup, errs := convertAWSEC2SecurityGroupToFern(context.Background(), aws.Config{}, types.SecurityGroup{}, "us-east-1")

	require.Nil(t, securityGroup)
	require.Equal(t, []string{"EC2 security group ID is missing"}, errs)
}

func TestConvertEC2SecurityGroupRuleIncludesPrefixListPeer(t *testing.T) {
	t.Parallel()

	rule, err := convertAWSEC2SecurityGroupRuleToFern(types.SecurityGroupRule{
		SecurityGroupRuleId: aws.String("sgr-0123456789abcdef0"),
		PrefixListId:        aws.String("pl-0123456789abcdef0"),
		IpProtocol:          aws.String("tcp"),
		FromPort:            aws.Int32(443),
		ToPort:              aws.Int32(443),
	})

	require.NoError(t, err)
	require.NotNil(t, rule)
	assert.Equal(t, "pl-0123456789abcdef0", aws.ToString(rule.Configuration.Peer.PrefixListId))
}

func TestConvertEC2SecurityGroupRuleKeepsMissingReferencedGroupOwnerUnset(t *testing.T) {
	t.Parallel()

	rule, err := convertAWSEC2SecurityGroupRuleToFern(types.SecurityGroupRule{
		SecurityGroupRuleId: aws.String("sgr-0123456789abcdef0"),
		ReferencedGroupInfo: &types.ReferencedSecurityGroup{GroupId: aws.String("sg-0123456789abcdef0")},
	})

	require.NoError(t, err)
	assert.Nil(t, rule.Configuration.Peer.ReferencedSecurityGroup.UserId)
}

package securitygroup

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

func TestConvertEC2SecurityGroupRequiresID(t *testing.T) {
	securityGroup, errs := convertAWSEC2SecurityGroupToFern(context.Background(), aws.Config{}, types.SecurityGroup{}, "us-east-1")

	require.Nil(t, securityGroup)
	require.Equal(t, []string{"EC2 security group ID is missing"}, errs)
}

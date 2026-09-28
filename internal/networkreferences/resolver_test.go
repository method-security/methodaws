package networkreferences

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

type stub struct {
	vpcCalls  int
	ownerID   string
	subnetARN string
}

func (s *stub) DescribeVpcs(_ context.Context, input *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	s.vpcCalls++
	return &ec2.DescribeVpcsOutput{Vpcs: []ec2types.Vpc{{VpcId: &input.VpcIds[0], OwnerId: &s.ownerID}}}, nil
}

func (s *stub) DescribeSubnets(_ context.Context, input *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if input.SubnetIds[0] == "subnet-denied" {
		return nil, fmt.Errorf("AccessDenied")
	}
	return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{
		SubnetId: &input.SubnetIds[0], OwnerId: &s.ownerID, SubnetArn: &s.subnetARN,
	}}}, nil
}

func (s *stub) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{
		GroupId: &input.GroupIds[0], OwnerId: aws.String("123456789012"), GroupName: aws.String("database-access"),
	}}}, nil
}

func TestResolverUsesReportedOwnersAndKeepsResolvedChildren(t *testing.T) {
	resolver := New(&stub{ownerID: "210987654321"}, "us-east-1")

	vpc, errs := resolver.Vpc(context.Background(), "vpc-aaaaaaaa", []string{"subnet-aaaaaaaa", "subnet-denied"})
	require.Len(t, errs, 1)
	require.Equal(t, "arn:aws:ec2:us-east-1:210987654321:vpc/vpc-aaaaaaaa", vpc.Arn)
	require.Equal(t, "210987654321", vpc.OwnerId)
	require.Len(t, vpc.Subnets, 1)
	require.Equal(t, "arn:aws:ec2:us-east-1:210987654321:subnet/subnet-aaaaaaaa", vpc.Subnets[0].Arn)

	groups, errs := resolver.SecurityGroups(context.Background(), []string{"sg-aaaaaaaa"})
	require.Empty(t, errs)
	require.Len(t, groups, 1)
	require.Equal(t, "arn:aws:ec2:us-east-1:123456789012:security-group/sg-aaaaaaaa", groups[0].Arn)
	require.Equal(t, "database-access", aws.ToString(groups[0].Name))
}

func TestResolverRejectsMismatchedReportedARNs(t *testing.T) {
	resolver := New(&stub{
		ownerID:   "210987654321",
		subnetARN: "arn:aws:ec2:us-west-2:210987654321:subnet/subnet-aaaaaaaa",
	}, "us-east-1")

	vpc, errs := resolver.Vpc(context.Background(), "vpc-aaaaaaaa", []string{"subnet-aaaaaaaa"})
	require.Len(t, errs, 1)
	require.NotNil(t, vpc)
	require.Empty(t, vpc.Subnets)
}

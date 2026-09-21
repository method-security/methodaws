package rds

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"
)

type networkStub struct {
	vpcCalls  int
	owner     string
	subnetARN string
}

func (s *networkStub) DescribeVpcs(_ context.Context, input *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	s.vpcCalls++
	return &ec2.DescribeVpcsOutput{Vpcs: []ec2types.Vpc{{VpcId: &input.VpcIds[0], OwnerId: &s.owner}}}, nil
}

func (s *networkStub) DescribeSubnets(_ context.Context, input *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if input.SubnetIds[0] == "subnet-bbbbbbbb" {
		return nil, fmt.Errorf("AccessDenied")
	}
	return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{SubnetId: &input.SubnetIds[0], OwnerId: &s.owner, SubnetArn: &s.subnetARN}}}, nil
}

func (s *networkStub) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: &input.GroupIds[0], OwnerId: aws.String("123456789012")}}}, nil
}

func TestNetworkReferencesUseActualOwnersAndKeepValidResults(t *testing.T) {
	stub := &networkStub{owner: "210987654321"}
	resolver := newNetworkResolver(stub, "us-east-1")
	source := types.DBInstance{
		DBInstanceIdentifier: aws.String("database"),
		DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:database"),
		DBSubnetGroup: &types.DBSubnetGroup{
			VpcId:   aws.String("vpc-aaaaaaaa"),
			Subnets: []types.Subnet{{SubnetIdentifier: aws.String("subnet-aaaaaaaa")}, {SubnetIdentifier: aws.String("subnet-bbbbbbbb")}},
		},
		VpcSecurityGroups: []types.VpcSecurityGroupMembership{{VpcSecurityGroupId: aws.String("sg-aaaaaaaa")}},
	}
	for range 2 {
		instance, errs := convertAWSDBInstanceToFern(source, "us-east-1")
		require.Empty(t, errs)
		errs = resolver.enrich(context.Background(), source, instance)
		require.Len(t, errs, 1)
		require.Contains(t, errs[0], "AccessDenied")
		require.Equal(t, "arn:aws:ec2:us-east-1:210987654321:vpc/vpc-aaaaaaaa", instance.Resources.Vpc.Arn)
		require.Len(t, instance.Resources.DbSubnetGroupSubnets, 1)
		require.Equal(t, "arn:aws:ec2:us-east-1:210987654321:subnet/subnet-aaaaaaaa", instance.Resources.DbSubnetGroupSubnets[0].Arn)
		require.Equal(t, "arn:aws:ec2:us-east-1:123456789012:security-group/sg-aaaaaaaa", instance.Resources.SecurityGroups[0].Arn)
		require.Len(t, instance.Configuration.DbSubnetGroupSubnetIds, 2)
	}
	require.Equal(t, 1, stub.vpcCalls)
}

func TestNetworkReferencesOmitUnresolvedIdentity(t *testing.T) {
	resolver := newNetworkResolver(&networkStub{}, "us-east-1")
	reference, err := resolver.resolve(context.Background(), "aws", "vpc", "vpc-aaaaaaaa")
	require.Error(t, err)
	require.Nil(t, reference)

	resolver = newNetworkResolver(&networkStub{
		owner: "210987654321", subnetARN: "arn:aws:ec2:us-west-2:210987654321:subnet/subnet-aaaaaaaa",
	}, "us-east-1")
	reference, err = resolver.resolve(context.Background(), "aws", "subnet", "subnet-aaaaaaaa")
	require.ErrorContains(t, err, "does not match")
	require.Nil(t, reference)
}

package rds

import (
	"context"
	"fmt"

	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type networkAPI interface {
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

type networkResult struct {
	reference *rdsfern.RdsNetworkResourceReference
	err       error
}

type networkResolver struct {
	client networkAPI
	region string
	cache  map[string]networkResult
}

func newNetworkResolver(client networkAPI, region string) *networkResolver {
	return &networkResolver{client: client, region: region, cache: make(map[string]networkResult)}
}

func (r *networkResolver) enrich(ctx context.Context, instance types.DBInstance, result *rdsfern.RdsInstance) []string {
	instanceARN, err := arn.Parse(result.Identification.Arn)
	if err != nil {
		return []string{fmt.Sprintf("cannot resolve network references: %s", err)}
	}
	var errors []string
	resolve := func(kind, id string) *rdsfern.RdsNetworkResourceReference {
		if id == "" {
			return nil // Missing IDs are already reported by the instance converter.
		}
		reference, err := r.resolve(ctx, instanceARN.Partition, kind, id)
		if err != nil {
			errors = append(errors, fmt.Sprintf("cannot resolve %s %q: %s", kind, id, err))
		}
		return reference
	}
	if instance.DBSubnetGroup != nil {
		result.Resources.Vpc = resolve("vpc", aws.ToString(instance.DBSubnetGroup.VpcId))
		for _, subnet := range instance.DBSubnetGroup.Subnets {
			if reference := resolve("subnet", aws.ToString(subnet.SubnetIdentifier)); reference != nil {
				result.Resources.DbSubnetGroupSubnets = append(result.Resources.DbSubnetGroupSubnets, reference)
			}
		}
	}
	for _, group := range instance.VpcSecurityGroups {
		if reference := resolve("security-group", aws.ToString(group.VpcSecurityGroupId)); reference != nil {
			result.Resources.SecurityGroups = append(result.Resources.SecurityGroups, reference)
		}
	}
	return errors
}

func (r *networkResolver) resolve(ctx context.Context, partition, kind, id string) (*rdsfern.RdsNetworkResourceReference, error) {
	key := partition + ":" + kind + "/" + id
	if cached, ok := r.cache[key]; ok {
		return cached.reference, cached.err
	}
	reference, err := r.lookup(ctx, partition, kind, id)
	r.cache[key] = networkResult{reference: reference, err: err}
	return reference, err
}

func (r *networkResolver) lookup(ctx context.Context, partition, kind, id string) (*rdsfern.RdsNetworkResourceReference, error) {
	var owner, reportedARN string
	var name *string
	// Each request targets one reported ID; never enumerate unrelated network resources.
	switch kind {
	case "vpc":
		output, err := r.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{id}})
		if err != nil {
			return nil, err
		}
		if output != nil {
			for _, vpc := range output.Vpcs {
				if aws.ToString(vpc.VpcId) == id {
					owner = aws.ToString(vpc.OwnerId)
				}
			}
		}
	case "subnet":
		output, err := r.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{id}})
		if err != nil {
			return nil, err
		}
		if output != nil {
			for _, subnet := range output.Subnets {
				if aws.ToString(subnet.SubnetId) == id {
					owner, reportedARN = aws.ToString(subnet.OwnerId), aws.ToString(subnet.SubnetArn)
				}
			}
		}
	case "security-group":
		output, err := r.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{id}})
		if err != nil {
			return nil, err
		}
		if output != nil {
			for _, group := range output.SecurityGroups {
				if aws.ToString(group.GroupId) == id {
					owner, reportedARN = aws.ToString(group.OwnerId), aws.ToString(group.SecurityGroupArn)
					name = group.GroupName
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported resource type %q", kind)
	}
	if owner == "" {
		return nil, fmt.Errorf("EC2 did not return the requested resource with an owner account")
	}
	resourceARN := arn.ARN{Partition: partition, Service: "ec2", Region: r.region, AccountID: owner, Resource: kind + "/" + id}.String()
	if reportedARN != "" && reportedARN != resourceARN {
		return nil, fmt.Errorf("reported ARN %q does not match the resource ID, owner, or region", reportedARN)
	}
	return &rdsfern.RdsNetworkResourceReference{
		Arn: resourceARN, Id: id, Region: r.region, OwnerId: owner, Name: name,
	}, nil
}

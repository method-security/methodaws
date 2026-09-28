package networkreferences

import (
	"context"
	"fmt"

	"github.com/Method-Security/methodaws/generated/go/common"
	"github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type API interface {
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

type reference struct {
	arn     string
	id      string
	region  string
	ownerID string
	name    *string
}

type result struct {
	reference *reference
	err       error
}

type Resolver struct {
	client API
	region string
	cache  map[string]result
}

func New(client API, region string) *Resolver {
	return &Resolver{client: client, region: region, cache: make(map[string]result)}
}

func (r *Resolver) Vpc(ctx context.Context, id string, subnetIDs []string) (*common.VpcReference, []error) {
	if id == "" {
		return nil, nil
	}
	vpc, err := r.resolve(ctx, "vpc", id)
	if err != nil {
		return nil, []error{err}
	}
	result := &common.VpcReference{
		Arn:     vpc.arn,
		Id:      vpc.id,
		Region:  vpc.region,
		OwnerId: vpc.ownerID,
	}
	var errors []error
	seen := make(map[string]bool)
	for _, subnetID := range subnetIDs {
		if subnetID == "" || seen[subnetID] {
			continue
		}
		seen[subnetID] = true
		subnet, err := r.resolve(ctx, "subnet", subnetID)
		if err != nil {
			errors = append(errors, fmt.Errorf("subnet %q: %w", subnetID, err))
			continue
		}
		result.Subnets = append(result.Subnets, &common.SubnetReference{
			Arn:     subnet.arn,
			Id:      subnet.id,
			Region:  subnet.region,
			OwnerId: subnet.ownerID,
		})
	}
	return result, errors
}

func (r *Resolver) SecurityGroups(ctx context.Context, ids []string) ([]*common.SecurityGroupReference, []error) {
	var references []*common.SecurityGroupReference
	var errors []error
	seen := make(map[string]bool)
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		reference, err := r.SecurityGroup(ctx, id)
		if err != nil {
			errors = append(errors, fmt.Errorf("security group %q: %w", id, err))
			continue
		}
		references = append(references, reference)
	}
	return references, errors
}

func (r *Resolver) SecurityGroup(ctx context.Context, id string) (*common.SecurityGroupReference, error) {
	if id == "" {
		return nil, nil
	}
	reference, err := r.resolve(ctx, "security-group", id)
	if err != nil {
		return nil, err
	}
	return &common.SecurityGroupReference{
		Arn:     reference.arn,
		Id:      reference.id,
		Region:  reference.region,
		OwnerId: reference.ownerID,
		Name:    reference.name,
	}, nil
}

func (r *Resolver) resolve(ctx context.Context, kind, id string) (*reference, error) {
	key := kind + "/" + id
	if cached, ok := r.cache[key]; ok {
		return cached.reference, cached.err
	}
	reference, err := r.lookup(ctx, kind, id)
	r.cache[key] = result{reference: reference, err: err}
	return reference, err
}

func (r *Resolver) lookup(ctx context.Context, kind, id string) (*reference, error) {
	var ownerID, reportedARN string
	var name *string
	switch kind {
	case "vpc":
		output, err := r.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{id}})
		if err != nil {
			return nil, err
		}
		if output != nil {
			for _, vpc := range output.Vpcs {
				if aws.ToString(vpc.VpcId) == id {
					ownerID = aws.ToString(vpc.OwnerId)
					break
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
					ownerID = aws.ToString(subnet.OwnerId)
					reportedARN = aws.ToString(subnet.SubnetArn)
					break
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
					ownerID = aws.ToString(group.OwnerId)
					reportedARN = aws.ToString(group.SecurityGroupArn)
					name = group.GroupName
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported resource type %q", kind)
	}
	if ownerID == "" {
		return nil, fmt.Errorf("EC2 did not return the requested resource with an owner account")
	}
	resourceARN, err := utils.BuildRegionalARN(r.region, "ec2", ownerID, kind+"/"+id)
	if err != nil {
		return nil, err
	}
	if reportedARN != "" && reportedARN != resourceARN {
		return nil, fmt.Errorf("reported ARN %q does not match the resource ID, owner, or region", reportedARN)
	}
	return &reference{arn: resourceARN, id: id, region: r.region, ownerID: ownerID, name: name}, nil
}

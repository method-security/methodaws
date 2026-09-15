package apigateway

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsgateway "github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubVpcLinkClient struct {
	output *awsgateway.GetVpcLinkOutput
	err    error
	calls  int
}

func (s *stubVpcLinkClient) GetVpcLink(
	context.Context,
	*awsgateway.GetVpcLinkInput,
	...func(*awsgateway.Options),
) (*awsgateway.GetVpcLinkOutput, error) {
	s.calls++
	return s.output, s.err
}

func TestConvertV1VpcLinkResolvesLoadBalancerTargets(t *testing.T) {
	t.Parallel()

	client := &stubVpcLinkClient{output: &awsgateway.GetVpcLinkOutput{TargetArns: []string{
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/example/abc",
	}}}
	cache := make(map[string][]string)
	integration := &types.Integration{
		Type:           types.IntegrationTypeHttpProxy,
		ConnectionType: types.ConnectionTypeVpcLink,
		ConnectionId:   aws.String("vpclink-123"),
		Uri:            aws.String("https://internal.example.invalid"),
	}

	converted, err := convertV1Integration(context.Background(), client, cache, integration, "us-east-1")
	require.NoError(t, err)
	require.NotNil(t, converted.VpcLink.Backend.LoadBalancer)
	backend := converted.VpcLink.Backend.LoadBalancer
	assert.Equal(t, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/example/abc", aws.ToString(backend.LoadBalancerArn))
	assert.Equal(t, []string{aws.ToString(backend.LoadBalancerArn)}, backend.LoadBalancerArns)
	assert.Nil(t, backend.DnsName)

	_, err = convertV1Integration(context.Background(), client, cache, integration, "us-east-1")
	require.NoError(t, err)
	assert.Equal(t, 1, client.calls)
}

func TestConvertV1VpcLinkRetainsIntegrationWhenTargetLookupFails(t *testing.T) {
	t.Parallel()

	client := &stubVpcLinkClient{err: errors.New("VPC Link lookup denied")}
	integration := &types.Integration{
		Type:           types.IntegrationTypeHttpProxy,
		ConnectionType: types.ConnectionTypeVpcLink,
		ConnectionId:   aws.String("vpclink-123"),
		Uri:            aws.String("https://internal.example.invalid"),
	}

	converted, err := convertV1Integration(context.Background(), client, make(map[string][]string), integration, "us-east-1")

	require.EqualError(t, err, "get VPC Link vpclink-123: VPC Link lookup denied")
	require.NotNil(t, converted)
	require.NotNil(t, converted.VpcLink.Backend.LoadBalancer)
	backend := converted.VpcLink.Backend.LoadBalancer
	assert.Equal(t, "https://internal.example.invalid", backend.Uri)
	assert.Equal(t, "vpclink-123", backend.VpcLinkId)
	assert.Nil(t, backend.LoadBalancerArn)
	assert.Nil(t, backend.LoadBalancerArns)
}

func TestConvertV1VpcLinkRejectsEmptyCachedTargetsWithoutPanicking(t *testing.T) {
	t.Parallel()

	cache := map[string][]string{"vpclink-123": {}}
	integration := &types.Integration{
		Type:           types.IntegrationTypeHttp,
		ConnectionType: types.ConnectionTypeVpcLink,
		ConnectionId:   aws.String("vpclink-123"),
		Uri:            aws.String("https://internal.example.invalid"),
	}

	converted, err := convertV1Integration(context.Background(), &stubVpcLinkClient{}, cache, integration, "us-east-1")

	require.EqualError(t, err, "VPC Link vpclink-123 has no target ARNs")
	require.NotNil(t, converted)
	assert.Equal(t, "vpclink-123", converted.VpcLink.Backend.LoadBalancer.VpcLinkId)
}

func TestConvertV1LambdaIntegrationExtractsFunctionARN(t *testing.T) {
	t.Parallel()

	integration := &types.Integration{
		Type: types.IntegrationTypeAwsProxy,
		Uri: aws.String(
			"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/" +
				"arn:aws:lambda:us-east-1:123456789012:function:test-function/invocations",
		),
	}

	converted, err := convertV1Integration(
		context.Background(),
		&stubVpcLinkClient{},
		make(map[string][]string),
		integration,
		"us-east-1",
	)

	require.NoError(t, err)
	require.NotNil(t, converted.AwsProxy)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:test-function", converted.AwsProxy.Backend.Arn)
	assert.Equal(t, "test-function", aws.ToString(converted.AwsProxy.Backend.FunctionName))
}

package apigateway

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsgateway "github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubVpcLinkClient struct {
	output *awsgateway.GetVpcLinkOutput
	calls  int
}

func (s *stubVpcLinkClient) GetVpcLink(
	context.Context,
	*awsgateway.GetVpcLinkInput,
	...func(*awsgateway.Options),
) (*awsgateway.GetVpcLinkOutput, error) {
	s.calls++
	return s.output, nil
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
	assert.Equal(t, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/example/abc", backend.LoadBalancerArn)
	assert.Equal(t, backend.LoadBalancerArns, []string{backend.LoadBalancerArn})
	assert.Nil(t, backend.DnsName)

	_, err = convertV1Integration(context.Background(), client, cache, integration, "us-east-1")
	require.NoError(t, err)
	assert.Equal(t, 1, client.calls)
}

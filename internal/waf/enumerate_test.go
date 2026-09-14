package waf

import (
	"context"
	"errors"
	"testing"

	waffern "github.com/Method-Security/methodaws/generated/go/waf"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubWAFClient struct {
	listOutputs       []*wafv2.ListWebACLsOutput
	listScopes        []types.Scope
	resourceListCalls int
	resourceTypes     []types.ResourceType
	resourceErrors    map[types.ResourceType]error
}

func (s *stubWAFClient) ListWebACLs(
	_ context.Context,
	input *wafv2.ListWebACLsInput,
	_ ...func(*wafv2.Options),
) (*wafv2.ListWebACLsOutput, error) {
	s.listScopes = append(s.listScopes, input.Scope)
	output := s.listOutputs[0]
	s.listOutputs = s.listOutputs[1:]
	return output, nil
}

func (s *stubWAFClient) GetWebACL(
	context.Context,
	*wafv2.GetWebACLInput,
	...func(*wafv2.Options),
) (*wafv2.GetWebACLOutput, error) {
	return &wafv2.GetWebACLOutput{WebACL: &types.WebACL{DefaultAction: &types.DefaultAction{Allow: &types.AllowAction{}}}}, nil
}

func (s *stubWAFClient) ListResourcesForWebACL(
	_ context.Context,
	input *wafv2.ListResourcesForWebACLInput,
	_ ...func(*wafv2.Options),
) (*wafv2.ListResourcesForWebACLOutput, error) {
	s.resourceListCalls++
	s.resourceTypes = append(s.resourceTypes, input.ResourceType)
	if err := s.resourceErrors[input.ResourceType]; err != nil {
		return nil, err
	}
	if input.ResourceType == types.ResourceTypeApplicationLoadBalancer {
		return &wafv2.ListResourcesForWebACLOutput{ResourceArns: []string{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/abc",
		}}, nil
	}
	return &wafv2.ListResourcesForWebACLOutput{ResourceArns: []string{
		"arn:aws:apigateway:us-east-1::/restapis/api-id/stages/prod",
	}}, nil
}

func TestCloudFrontWAFRegionRequiresCommercialPartition(t *testing.T) {
	t.Parallel()

	region, ok := cloudFrontWAFRegion("", []string{"us-west-2"})
	assert.True(t, ok)
	assert.Equal(t, "us-east-1", region)

	_, ok = cloudFrontWAFRegion("", []string{"us-gov-west-1"})
	assert.False(t, ok)
	_, ok = cloudFrontWAFRegion("", []string{"cn-north-1"})
	assert.False(t, ok)
}

func TestResourcesForWebACLContinuesAfterOneResourceTypeFails(t *testing.T) {
	t.Parallel()

	client := &stubWAFClient{resourceErrors: map[types.ResourceType]error{
		types.ResourceTypeApplicationLoadBalancer: errors.New("load balancer associations denied"),
	}}
	resources, errs := resourcesForWebACL(context.Background(), client, aws.String("web-acl"), "us-east-1")

	require.Equal(t, []string{"load balancer associations denied"}, errs)
	assert.Equal(t, 2, client.resourceListCalls)
	require.Len(t, resources, 1)
	assert.Contains(t, resources[0], ":apigateway:")
}

func TestEnumerateWAFForScopePaginatesAndListsAssociationsOnce(t *testing.T) {
	client := &stubWAFClient{listOutputs: []*wafv2.ListWebACLsOutput{
		{NextMarker: aws.String("next")},
		{WebACLs: []types.WebACLSummary{{
			ARN: aws.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/example/id"),
			Id:  aws.String("id"), Name: aws.String("example"),
		}}},
	}}

	wafs, errs := enumerateWAFForScope(
		context.Background(), client, "us-east-1", types.ScopeRegional, waffern.ScopeTypeRegional,
	)

	require.Empty(t, errs)
	require.Len(t, wafs, 1)
	assert.Equal(t, []types.Scope{types.ScopeRegional, types.ScopeRegional}, client.listScopes)
	assert.Equal(t, 2, client.resourceListCalls)
	assert.Equal(t, []types.ResourceType{
		types.ResourceTypeApplicationLoadBalancer,
		types.ResourceTypeApiGateway,
	}, client.resourceTypes)
	assert.NotNil(t, wafs[0].Resources.LoadBalancer)
	assert.NotNil(t, wafs[0].Resources.ApiGateway)
}

func TestEnumerateCloudFrontWAFDoesNotListRegionalAssociations(t *testing.T) {
	client := &stubWAFClient{listOutputs: []*wafv2.ListWebACLsOutput{{WebACLs: []types.WebACLSummary{{
		ARN: aws.String("arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/id"),
		Id:  aws.String("id"), Name: aws.String("example"),
	}}}}}

	wafs, errs := enumerateWAFForScope(
		context.Background(), client, "us-east-1", types.ScopeCloudfront, waffern.ScopeTypeCloudfront,
	)

	require.Empty(t, errs)
	require.Len(t, wafs, 1)
	assert.Equal(t, waffern.ScopeTypeCloudfront, wafs[0].Configuration.Scope)
	assert.Zero(t, client.resourceListCalls)
}

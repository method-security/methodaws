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
	getOutput         *wafv2.GetWebACLOutput
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
	if s.getOutput != nil {
		return s.getOutput, nil
	}
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
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/first/abc",
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/second/def",
		}}, nil
	}
	return &wafv2.ListResourcesForWebACLOutput{ResourceArns: []string{
		"arn:aws:apigateway:us-east-1::/restapis/first-api/stages/prod",
		"arn:aws:apigateway:us-east-1::/restapis/second-api/stages/prod",
	}}, nil
}

func TestCloudFrontWAFRegionRequiresCommercialPartition(t *testing.T) {
	t.Parallel()

	region, ok := cloudFrontWAFRegion("", []string{"us-west-2"})
	assert.True(t, ok)
	assert.Equal(t, "us-east-1", region)
	region, ok = cloudFrontWAFRegion("", []string{"mx-central-1"})
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

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "load balancer associations denied")
	assert.Equal(t, 2, client.resourceListCalls)
	require.Len(t, resources, 2)
	assert.Contains(t, resources[0], ":apigateway:")
	assert.Contains(t, resources[1], ":apigateway:")
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
	require.Len(t, wafs[0].Resources.LoadBalancers, 2)
	assert.Equal(t, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/first/abc",
		wafs[0].Resources.LoadBalancers[0].Arn)
	assert.Equal(t, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/second/def",
		wafs[0].Resources.LoadBalancers[1].Arn)
	require.Len(t, wafs[0].Configuration.ApiGatewayStageAssociations, 2)
	assert.Equal(t, "first-api", *wafs[0].Configuration.ApiGatewayStageAssociations[0].Api.ApiId)
	assert.Equal(t, "second-api", *wafs[0].Configuration.ApiGatewayStageAssociations[1].Api.ApiId)
	assert.Equal(t, "arn:aws:apigateway:us-east-1::/restapis/first-api", wafs[0].Configuration.ApiGatewayStageAssociations[0].Api.Arn)
	assert.Equal(t, "arn:aws:apigateway:us-east-1::/restapis/first-api/stages/prod", wafs[0].Configuration.ApiGatewayStageAssociations[0].StageArn)
	assert.Equal(t, "prod", wafs[0].Configuration.ApiGatewayStageAssociations[0].StageName)
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

func TestEnumerateWAFSkipsRuleWithMissingStatement(t *testing.T) {
	t.Parallel()

	client := &stubWAFClient{
		listOutputs: []*wafv2.ListWebACLsOutput{{WebACLs: []types.WebACLSummary{{
			ARN: aws.String("arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/id"),
			Id:  aws.String("id"), Name: aws.String("example"),
		}}}},
		getOutput: &wafv2.GetWebACLOutput{WebACL: &types.WebACL{
			DefaultAction: &types.DefaultAction{Allow: &types.AllowAction{}},
			Rules: []types.Rule{
				{Name: aws.String("incomplete")},
				{Name: aws.String("valid"), Statement: &types.Statement{ByteMatchStatement: &types.ByteMatchStatement{}}, Action: &types.RuleAction{Allow: &types.AllowAction{}}},
			},
		}},
	}

	wafs, errs := enumerateWAFForScope(
		context.Background(), client, "us-east-1", types.ScopeCloudfront, waffern.ScopeTypeCloudfront,
	)

	require.Len(t, wafs, 1)
	require.Len(t, wafs[0].Resources.Rules, 1)
	assert.Equal(t, "valid", wafs[0].Resources.Rules[0].Identification.Name)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "WAF Rule incomplete Statement is nil")
}

func TestRuleActionsAndScopedIdentity(t *testing.T) {
	const parent = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/example/id"
	client := &stubWAFClient{getOutput: &wafv2.GetWebACLOutput{WebACL: &types.WebACL{
		DefaultAction: &types.DefaultAction{Block: &types.BlockAction{}},
		Rules: []types.Rule{
			{Name: aws.String("default"), Statement: &types.Statement{ByteMatchStatement: &types.ByteMatchStatement{}},
				Action: &types.RuleAction{Allow: &types.AllowAction{}}, RuleLabels: []types.Label{{Name: aws.String("app:allowed")}}},
			{Name: aws.String("managed"), Statement: &types.Statement{ManagedRuleGroupStatement: &types.ManagedRuleGroupStatement{}},
				OverrideAction: &types.OverrideAction{None: &types.NoneAction{}}},
			{Name: aws.String("count-group"), Statement: &types.Statement{RuleGroupReferenceStatement: &types.RuleGroupReferenceStatement{}},
				OverrideAction: &types.OverrideAction{Count: &types.CountAction{}}},
			{Name: aws.String("missing-action"), Statement: &types.Statement{ByteMatchStatement: &types.ByteMatchStatement{}}},
			{Name: aws.String("multiple-actions"), Statement: &types.Statement{ByteMatchStatement: &types.ByteMatchStatement{}},
				Action: &types.RuleAction{Allow: &types.AllowAction{}, Block: &types.BlockAction{}}},
			{Name: aws.String("wrong-group-action"), Statement: &types.Statement{ManagedRuleGroupStatement: &types.ManagedRuleGroupStatement{}},
				Action: &types.RuleAction{Allow: &types.AllowAction{}}},
			{Name: aws.String("empty-override"), Statement: &types.Statement{ManagedRuleGroupStatement: &types.ManagedRuleGroupStatement{}},
				OverrideAction: &types.OverrideAction{}},
		},
	}}}
	rules, defaultAction, errs := getRules(context.Background(), client, types.ScopeRegional, aws.String("id"), aws.String("example"), parent)
	require.Len(t, rules, 3)
	require.Len(t, errs, 4)
	require.NotNil(t, defaultAction)
	assert.Equal(t, waffern.ActionTypeBlock, *defaultAction)
	assert.Equal(t, parent+"/rule/default", rules[0].Identification.Id)
	assert.Equal(t, waffern.ActionTypeAllow, rules[0].Configuration.Action.Type)
	assert.Equal(t, []string{"app:allowed"}, rules[0].Configuration.Labels)
	assert.Nil(t, rules[1].Configuration.Action)
	assert.Equal(t, waffern.OverrideActionTypeNone, *rules[1].Configuration.OverrideAction)
	assert.Equal(t, waffern.OverrideActionTypeCount, *rules[2].Configuration.OverrideAction)
	assert.Contains(t, rules[1].Configuration.RawRule, "OverrideAction")
}

package loadbalancer

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubELBV2ResourceClient struct {
	targetGroupInput  *elasticloadbalancingv2.DescribeTargetGroupsInput
	targetGroupOutput *elasticloadbalancingv2.DescribeTargetGroupsOutput
	certificatePages  []*elasticloadbalancingv2.DescribeListenerCertificatesOutput
	targetHealth      *elasticloadbalancingv2.DescribeTargetHealthOutput
	targetHealthErr   error
	listenerOutput    *elasticloadbalancingv2.DescribeListenersOutput
	certificateErr    error
}

func (s *stubELBV2ResourceClient) DescribeListeners(
	context.Context,
	*elasticloadbalancingv2.DescribeListenersInput,
	...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	if s.listenerOutput != nil {
		return s.listenerOutput, nil
	}
	return &elasticloadbalancingv2.DescribeListenersOutput{}, nil
}

func (s *stubELBV2ResourceClient) DescribeListenerCertificates(
	_ context.Context,
	_ *elasticloadbalancingv2.DescribeListenerCertificatesInput,
	_ ...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeListenerCertificatesOutput, error) {
	if s.certificateErr != nil {
		return nil, s.certificateErr
	}
	output := s.certificatePages[0]
	s.certificatePages = s.certificatePages[1:]
	return output, nil
}

func TestListenerRetainsDefaultCertificateWhenCertificateListingFails(t *testing.T) {
	t.Parallel()

	client := &stubELBV2ResourceClient{
		listenerOutput: &elasticloadbalancingv2.DescribeListenersOutput{Listeners: []elbv2types.Listener{{
			ListenerArn: aws.String("listener"),
			Certificates: []elbv2types.Certificate{{
				CertificateArn: aws.String("default-certificate"),
			}}},
		}},
		certificateErr: errors.New("certificate listing denied"),
	}

	listeners, errs := listenersForLoadBalancerV2(context.Background(), client, aws.String("load-balancer"))

	require.Len(t, errs, 1)
	require.Contains(t, errs[0], "certificate listing denied")
	require.Len(t, listeners, 1)
	require.Len(t, listeners[0].Certificates, 1)
	assert.Equal(t, "default-certificate", listeners[0].Certificates[0].Arn)
	assert.True(t, listeners[0].Certificates[0].IsDefault)
}

func TestListenerCertificateMergePreservesDefaultFlag(t *testing.T) {
	t.Parallel()

	client := &stubELBV2ResourceClient{
		listenerOutput: &elasticloadbalancingv2.DescribeListenersOutput{Listeners: []elbv2types.Listener{{
			ListenerArn: aws.String("listener"),
			Certificates: []elbv2types.Certificate{{
				CertificateArn: aws.String("default-certificate"),
			}},
		}}},
		certificatePages: []*elasticloadbalancingv2.DescribeListenerCertificatesOutput{{
			Certificates: []elbv2types.Certificate{{
				CertificateArn: aws.String("default-certificate"),
				IsDefault:      aws.Bool(true),
			}},
		}},
	}

	listeners, errs := listenersForLoadBalancerV2(context.Background(), client, aws.String("load-balancer"))

	require.Empty(t, errs)
	require.Len(t, listeners, 1)
	require.Len(t, listeners[0].Certificates, 1)
	assert.True(t, listeners[0].Certificates[0].IsDefault)
}

func (s *stubELBV2ResourceClient) DescribeTargetGroups(
	_ context.Context,
	input *elasticloadbalancingv2.DescribeTargetGroupsInput,
	_ ...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	s.targetGroupInput = input
	if s.targetGroupOutput != nil {
		return s.targetGroupOutput, nil
	}
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{}, nil
}

func (s *stubELBV2ResourceClient) DescribeTargetHealth(
	context.Context,
	*elasticloadbalancingv2.DescribeTargetHealthInput,
	...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return s.targetHealth, s.targetHealthErr
}

func TestTargetGroupsUseLoadBalancerFilter(t *testing.T) {
	client := &stubELBV2ResourceClient{}
	lbARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/id"

	_, errs := targetGroupForLoadBalancerV2(context.Background(), client, &lbARN, "us-east-1")

	require.Empty(t, errs)
	require.NotNil(t, client.targetGroupInput)
	assert.Equal(t, lbARN, aws.ToString(client.targetGroupInput.LoadBalancerArn))
}

func TestListenerCertificatesCollectEveryPage(t *testing.T) {
	client := &stubELBV2ResourceClient{certificatePages: []*elasticloadbalancingv2.DescribeListenerCertificatesOutput{
		{Certificates: []elbv2types.Certificate{{CertificateArn: aws.String("first")}}, NextMarker: aws.String("next")},
		{Certificates: []elbv2types.Certificate{{CertificateArn: aws.String("second")}}},
	}}

	certificates, errs := certificatesForListenerV2(context.Background(), client, aws.String("listener"))

	require.Empty(t, errs)
	require.Len(t, certificates, 2)
	assert.Equal(t, "first", certificates[0].Arn)
	assert.Equal(t, "second", certificates[1].Arn)
}

func TestTargetPortRemainsUnsetWhenAWSOmitsIt(t *testing.T) {
	client := &stubELBV2ResourceClient{targetHealth: &elasticloadbalancingv2.DescribeTargetHealthOutput{
		TargetHealthDescriptions: []elbv2types.TargetHealthDescription{
			{Target: &elbv2types.TargetDescription{Id: aws.String("instance-id")}},
			{Target: nil},
		},
	}}

	targets, err := targetsForTargetGroupV2(context.Background(), client, elbv2types.TargetGroup{
		TargetGroupArn: aws.String("target-group"),
		TargetType:     elbv2types.TargetTypeEnumInstance,
	})

	require.ErrorContains(t, err, "target without an ID")
	require.Len(t, targets, 1)
	assert.Nil(t, targets[0].Port)
}

func TestTargetGroupIsRetainedWhenTargetHealthIsUnavailable(t *testing.T) {
	t.Parallel()

	client := &stubELBV2ResourceClient{
		targetGroupOutput: &elasticloadbalancingv2.DescribeTargetGroupsOutput{TargetGroups: []elbv2types.TargetGroup{{
			TargetGroupArn:  aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/id"),
			TargetGroupName: aws.String("example"),
		}}},
		targetHealthErr: errors.New("target health denied"),
	}
	lbARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/id"

	targetGroups, errs := targetGroupForLoadBalancerV2(context.Background(), client, &lbARN, "us-east-1")

	require.Len(t, errs, 1)
	require.Contains(t, errs[0], "target health denied")
	require.Len(t, targetGroups, 1)
	assert.Equal(t,
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/id",
		targetGroups[0].Identification.Arn,
	)
	assert.Nil(t, targetGroups[0].Resources)
}

func TestListenerDefaultForwardTargets(t *testing.T) {
	first := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/first/123"
	second := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/second/456"
	client := &stubELBV2ResourceClient{listenerOutput: &elasticloadbalancingv2.DescribeListenersOutput{
		Listeners: []elbv2types.Listener{{
			ListenerArn: aws.String("listener"),
			DefaultActions: []elbv2types.Action{
				{Type: elbv2types.ActionTypeEnumAuthenticateOidc},
				{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: aws.String(first),
					ForwardConfig: &elbv2types.ForwardActionConfig{TargetGroups: []elbv2types.TargetGroupTuple{
						{TargetGroupArn: aws.String(first), Weight: aws.Int32(100)},
						{TargetGroupArn: aws.String(second), Weight: aws.Int32(0)},
						{TargetGroupArn: aws.String("invalid")},
					}}},
			},
		}},
	}}
	listeners, errs := listenersForLoadBalancerV2(context.Background(), client, aws.String("load-balancer"))
	require.Len(t, errs, 1)
	require.Len(t, listeners, 1)
	targets := listeners[0].DefaultForwardTargetGroups
	require.Len(t, targets, 2)
	assert.Equal(t, first, targets[0].Arn)
	assert.Equal(t, 100, aws.ToInt(targets[0].Weight))
	assert.Equal(t, second, targets[1].Arn)
	require.NotNil(t, targets[1].Weight)
	assert.Zero(t, *targets[1].Weight)
}

func TestDefaultForwardTargetWithoutWeightedConfiguration(t *testing.T) {
	groupARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/example/123"
	targets, errs := defaultForwardTargetGroups([]elbv2types.Action{
		{Type: elbv2types.ActionTypeEnumRedirect, TargetGroupArn: aws.String(groupARN)},
		{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: aws.String(groupARN)},
		{Type: elbv2types.ActionTypeEnumForward},
	})
	require.Len(t, errs, 1)
	require.Len(t, targets, 1)
	assert.Equal(t, groupARN, targets[0].Arn)
	assert.Nil(t, targets[0].Weight)
}

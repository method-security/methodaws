package loadbalancer

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubELBV2ResourceClient struct {
	targetGroupInput *elasticloadbalancingv2.DescribeTargetGroupsInput
	certificatePages []*elasticloadbalancingv2.DescribeListenerCertificatesOutput
	targetHealth     *elasticloadbalancingv2.DescribeTargetHealthOutput
}

func (s *stubELBV2ResourceClient) DescribeListeners(
	context.Context,
	*elasticloadbalancingv2.DescribeListenersInput,
	...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	return &elasticloadbalancingv2.DescribeListenersOutput{}, nil
}

func (s *stubELBV2ResourceClient) DescribeListenerCertificates(
	_ context.Context,
	_ *elasticloadbalancingv2.DescribeListenerCertificatesInput,
	_ ...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeListenerCertificatesOutput, error) {
	output := s.certificatePages[0]
	s.certificatePages = s.certificatePages[1:]
	return output, nil
}

func (s *stubELBV2ResourceClient) DescribeTargetGroups(
	_ context.Context,
	input *elasticloadbalancingv2.DescribeTargetGroupsInput,
	_ ...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	s.targetGroupInput = input
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{}, nil
}

func (s *stubELBV2ResourceClient) DescribeTargetHealth(
	context.Context,
	*elasticloadbalancingv2.DescribeTargetHealthInput,
	...func(*elasticloadbalancingv2.Options),
) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return s.targetHealth, nil
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

	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Nil(t, targets[0].Port)
}

func TestClassicTargetPortRequiresOneUnambiguousBackendPort(t *testing.T) {
	loadBalancer := types.LoadBalancerDescription{
		Instances: []types.Instance{{InstanceId: aws.String("instance-id")}},
		ListenerDescriptions: []types.ListenerDescription{
			{Listener: &types.Listener{InstancePort: aws.Int32(8080)}},
			{Listener: &types.Listener{InstancePort: aws.Int32(8443)}},
		},
	}

	targets, errs := targetsForLoadBalancerV1(loadBalancer)

	require.Empty(t, errs)
	require.Len(t, targets, 1)
	assert.Nil(t, targets[0].Port)
}

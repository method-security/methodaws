package loadbalancer

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassicTargetPortsAreNotInferredFromListeners(t *testing.T) {
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

	loadBalancer.ListenerDescriptions = loadBalancer.ListenerDescriptions[:1]
	targets, errs = targetsForLoadBalancerV1(loadBalancer)
	require.Empty(t, errs)
	require.Len(t, targets, 1)
	assert.Nil(t, targets[0].Port)
}

func TestClassicLoadBalancerUsesAuthoritativeARNAndOptionalListenerARN(t *testing.T) {
	t.Parallel()

	loadBalancer := types.LoadBalancerDescription{
		LoadBalancerName: aws.String("example"),
		ListenerDescriptions: []types.ListenerDescription{{
			Listener: &types.Listener{LoadBalancerPort: 443},
		}},
	}

	identification, err := classicLoadBalancerIdentification(loadBalancer, "us-gov-west-1", "123456789012")
	require.NoError(t, err)
	assert.Equal(t,
		"arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:123456789012:loadbalancer/example",
		identification.Arn,
	)

	listeners, errs := listenersForLoadBalancerV1(loadBalancer)
	require.Empty(t, errs)
	require.Len(t, listeners, 1)
	assert.Nil(t, listeners[0].Arn)
	assert.Equal(t, 443, aws.ToInt(listeners[0].Port))
}

func TestClassicListenerBackendSettingsRemainPerListener(t *testing.T) {
	listeners, errs := listenersForLoadBalancerV1(types.LoadBalancerDescription{
		ListenerDescriptions: []types.ListenerDescription{
			{Listener: &types.Listener{LoadBalancerPort: 80, InstancePort: aws.Int32(8080), InstanceProtocol: aws.String("HTTP")}},
			{Listener: &types.Listener{LoadBalancerPort: 443, InstancePort: aws.Int32(8443), InstanceProtocol: aws.String("HTTPS")}},
			{Listener: &types.Listener{LoadBalancerPort: 9000, InstancePort: aws.Int32(0), InstanceProtocol: aws.String("invalid")}},
		},
	})
	require.Len(t, errs, 2)
	require.Len(t, listeners, 3)
	assert.Equal(t, 8080, aws.ToInt(listeners[0].BackendPort))
	require.NotNil(t, listeners[0].BackendProtocol)
	assert.Equal(t, "HTTP", string(*listeners[0].BackendProtocol))
	assert.Equal(t, 8443, aws.ToInt(listeners[1].BackendPort))
	require.NotNil(t, listeners[1].BackendProtocol)
	assert.Equal(t, "HTTPS", string(*listeners[1].BackendProtocol))
	assert.Nil(t, listeners[2].BackendPort)
	assert.Nil(t, listeners[2].BackendProtocol)
}

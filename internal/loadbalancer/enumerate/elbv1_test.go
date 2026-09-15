package loadbalancer

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

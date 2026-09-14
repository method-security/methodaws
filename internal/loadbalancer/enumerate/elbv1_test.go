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

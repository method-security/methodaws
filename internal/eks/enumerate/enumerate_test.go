package eks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCloudWatchLogReferenceUsesClusterIdentity(t *testing.T) {
	t.Parallel()

	reference := createCloudWatchLogReference(
		"/aws/eks/example/cluster",
		"arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/example",
		"us-gov-west-1",
	)

	require.NotNil(t, reference)
	assert.Equal(
		t,
		"arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/eks/example/cluster",
		reference.Arn,
	)
}

func TestCreateCloudWatchLogReferenceRejectsInvalidClusterARN(t *testing.T) {
	t.Parallel()

	assert.Nil(t, createCloudWatchLogReference("/aws/eks/example/cluster", "example", "us-east-1"))
}

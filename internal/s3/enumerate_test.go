package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKmsKeyReferenceRequiresKeyARN(t *testing.T) {
	t.Parallel()

	reference := kmsKeyReference("arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abcd-1234")

	require.NotNil(t, reference)
	assert.Equal(t, "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abcd-1234", reference.Arn)
	assert.Equal(t, "abcd-1234", reference.KeyId)
	assert.Equal(t, "us-gov-west-1", reference.Region)
}

func TestKmsKeyReferenceRejectsIdentifiersThatAreNotKeyARNs(t *testing.T) {
	t.Parallel()

	assert.Nil(t, kmsKeyReference("abcd-1234"))
	assert.Nil(t, kmsKeyReference("alias/example"))
	assert.Nil(t, kmsKeyReference("arn:aws:kms:us-east-1:123456789012:alias/example"))
}

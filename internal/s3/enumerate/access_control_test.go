package enumerate

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateS3AccessKnownPrivateBucket(t *testing.T) {
	t.Parallel()

	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:                testBucketARN,
		aclKnown:                 true,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.False(t, aws.ToBool(accessControl.AllowPublicRead))
	assert.False(t, aws.ToBool(accessControl.AllowPublicWrite))
	assert.False(t, aws.ToBool(accessControl.AllowAuthenticatedUsersRead))
	assert.False(t, aws.ToBool(accessControl.AllowAuthenticatedUsersWrite))
	assert.False(t, aws.ToBool(accessControl.BlockPublicAcls))
	assert.False(t, aws.ToBool(accessControl.RestrictPublicBuckets))
	require.NotNil(t, accessControl.PublicAccessBlock)
	require.NotNil(t, accessControl.PublicAccessBlock.Bucket)
	require.NotNil(t, accessControl.PublicAccessBlock.EffectiveAccount)
	require.NotNil(t, accessControl.PublicAccessBlock.Effective)
	assert.False(t, aws.ToBool(accessControl.PublicAccessBlock.Bucket.BlockPublicAcls))
	assert.False(t, aws.ToBool(accessControl.PublicAccessBlock.EffectiveAccount.BlockPublicAcls))
	assert.False(t, aws.ToBool(accessControl.PublicAccessBlock.Effective.BlockPublicAcls))
}

func TestEvaluateACLPermissionsRecognizesAWSGroupGrants(t *testing.T) {
	t.Parallel()

	permissions := evaluateACLPermissions([]types.Grant{
		aclGrant(allUsersGroup, types.PermissionFullControl),
		aclGrant(authenticatedUsersGroup, types.PermissionWrite),
		aclGrant(logDeliveryGroup, types.PermissionFullControl),
	}, true)

	assert.True(t, aws.ToBool(permissions.publicRead))
	assert.True(t, aws.ToBool(permissions.publicWrite))
	assert.True(t, aws.ToBool(permissions.publicReadACP))
	assert.True(t, aws.ToBool(permissions.publicWriteACP))
	assert.True(t, aws.ToBool(permissions.publicFullControl))
	assert.True(t, aws.ToBool(permissions.authenticatedUsersWrite))
	assert.False(t, aws.ToBool(permissions.authenticatedUsersRead))
	assert.True(t, aws.ToBool(permissions.logDeliveryWrite))
	assert.True(t, aws.ToBool(permissions.logDeliveryReadACP))
}

func TestEvaluateS3AccessAppliesPublicAccessBlocks(t *testing.T) {
	t.Parallel()

	publicReadPolicy := `{
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::example-bucket/*"
		}]
	}`

	tests := []struct {
		name           string
		grants         []types.Grant
		policy         *string
		bucketPAB      publicAccessBlockState
		accountPAB     publicAccessBlockState
		publicRead     *bool
		ignoreACLs     *bool
		restrictPolicy *bool
	}{
		{
			name:           "bucket IgnorePublicAcls suppresses an existing public ACL",
			grants:         []types.Grant{aclGrant(allUsersGroup, types.PermissionRead)},
			bucketPAB:      knownPublicAccessBlock(false, true, false, false),
			accountPAB:     knownPublicAccessBlock(false, false, false, false),
			publicRead:     boolPointer(false),
			ignoreACLs:     boolPointer(true),
			restrictPolicy: boolPointer(false),
		},
		{
			name:           "account RestrictPublicBuckets suppresses an existing public policy",
			policy:         &publicReadPolicy,
			bucketPAB:      knownPublicAccessBlock(false, false, false, false),
			accountPAB:     knownPublicAccessBlock(false, false, false, true),
			publicRead:     boolPointer(false),
			ignoreACLs:     boolPointer(false),
			restrictPolicy: boolPointer(true),
		},
		{
			name:           "BlockPublicPolicy does not suppress an existing public policy",
			policy:         &publicReadPolicy,
			bucketPAB:      knownPublicAccessBlock(false, false, true, false),
			accountPAB:     knownPublicAccessBlock(false, false, false, false),
			publicRead:     boolPointer(true),
			ignoreACLs:     boolPointer(false),
			restrictPolicy: boolPointer(false),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			accessControl, err := evaluateS3Access(accessEvaluationInput{
				bucketARN:                testBucketARN,
				grants:                   test.grants,
				aclKnown:                 true,
				policyDocument:           test.policy,
				policyKnown:              true,
				bucketPublicAccessBlock:  test.bucketPAB,
				accountPublicAccessBlock: test.accountPAB,
			})

			require.NoError(t, err)
			require.NotNil(t, accessControl)
			assert.Equal(t, test.publicRead, accessControl.AllowPublicRead)
			assert.Equal(t, test.ignoreACLs, accessControl.IgnorePublicAcls)
			assert.Equal(t, test.restrictPolicy, accessControl.RestrictPublicBuckets)
		})
	}
}

func TestEvaluateS3AccessPreservesPublicAccessBlockLevels(t *testing.T) {
	t.Parallel()

	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:                testBucketARN,
		aclKnown:                 true,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(true, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, true, false, true),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	require.NotNil(t, accessControl.PublicAccessBlock)
	require.NotNil(t, accessControl.PublicAccessBlock.Bucket)
	require.NotNil(t, accessControl.PublicAccessBlock.EffectiveAccount)
	require.NotNil(t, accessControl.PublicAccessBlock.Effective)
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.Bucket.BlockPublicAcls))
	assert.False(t, aws.ToBool(accessControl.PublicAccessBlock.Bucket.IgnorePublicAcls))
	assert.False(t, aws.ToBool(accessControl.PublicAccessBlock.EffectiveAccount.BlockPublicAcls))
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.EffectiveAccount.IgnorePublicAcls))
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.EffectiveAccount.RestrictPublicBuckets))
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.Effective.BlockPublicAcls))
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.Effective.IgnorePublicAcls))
	assert.True(t, aws.ToBool(accessControl.PublicAccessBlock.Effective.RestrictPublicBuckets))
}

func TestEvaluateS3AccessLeavesUnavailablePublicAccessBlockLevelUnset(t *testing.T) {
	t.Parallel()

	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:               testBucketARN,
		aclKnown:                true,
		policyKnown:             true,
		bucketPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	require.NotNil(t, accessControl.PublicAccessBlock)
	require.NotNil(t, accessControl.PublicAccessBlock.Bucket)
	assert.Nil(t, accessControl.PublicAccessBlock.EffectiveAccount)
	assert.Nil(t, accessControl.PublicAccessBlock.Effective)
}

func TestEvaluateS3AccessRequiresEveryACLReadOperationToBeDenied(t *testing.T) {
	t.Parallel()

	denyPublicRead := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::example-bucket"
		}]
	}`
	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:                testBucketARN,
		grants:                   []types.Grant{aclGrant(allUsersGroup, types.PermissionRead)},
		aclKnown:                 true,
		policyDocument:           &denyPublicRead,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.Equal(t, boolPointer(true), accessControl.AllowPublicRead)
}

func TestEvaluateS3AccessAppliesCompletePolicyDenyToACLRead(t *testing.T) {
	t.Parallel()

	denyPublicRead := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
			"Resource": "arn:aws:s3:::example-bucket"
		}]
	}`
	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:                testBucketARN,
		grants:                   []types.Grant{aclGrant(allUsersGroup, types.PermissionRead)},
		aclKnown:                 true,
		policyDocument:           &denyPublicRead,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicRead)
}

func TestEvaluateS3AccessAppliesPutObjectDenyToACLWrite(t *testing.T) {
	t.Parallel()

	denyPublicWrite := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::example-bucket/*"
		}]
	}`
	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN: testBucketARN,
		grants: []types.Grant{
			aclGrant(allUsersGroup, types.PermissionWrite),
			aclGrant(logDeliveryGroup, types.PermissionWrite),
		},
		aclKnown:                 true,
		policyDocument:           &denyPublicWrite,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicWrite)
	assert.Equal(t, boolPointer(false), accessControl.AllowLogDeliveryWrite)
}

func TestEvaluateS3AccessDoesNotApplyObjectDenyToBucketWideACLWrite(t *testing.T) {
	t.Parallel()

	denySingleObject := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": ["s3:PutObject", "s3:DeleteObject"],
			"Resource": "arn:aws:s3:::example-bucket/object"
		}]
	}`
	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN: testBucketARN,
		grants: []types.Grant{
			aclGrant(allUsersGroup, types.PermissionWrite),
			aclGrant(logDeliveryGroup, types.PermissionWrite),
		},
		aclKnown:                 true,
		policyDocument:           &denySingleObject,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.Equal(t, boolPointer(true), accessControl.AllowPublicWrite)
	assert.Equal(t, boolPointer(true), accessControl.AllowLogDeliveryWrite)
}

func TestEvaluateS3AccessRecognizesDenyOutsideTrustedOrganization(t *testing.T) {
	t.Parallel()

	denyOutsideOrganization := `{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"],
			"Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}}
		}]
	}`
	accessControl, err := evaluateS3Access(accessEvaluationInput{
		bucketARN:                testBucketARN,
		grants:                   []types.Grant{aclGrant(allUsersGroup, types.PermissionFullControl)},
		aclKnown:                 true,
		policyDocument:           &denyOutsideOrganization,
		policyKnown:              true,
		bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
		accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
	})

	require.NoError(t, err)
	require.NotNil(t, accessControl)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicRead)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicWrite)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicReadAcp)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicWriteAcp)
	assert.Equal(t, boolPointer(false), accessControl.AllowPublicFullControl)
}

func TestEvaluateS3AccessLeavesUncertainResultsUnset(t *testing.T) {
	t.Parallel()

	t.Run("permissions API unavailable", func(t *testing.T) {
		t.Parallel()

		accessControl, err := evaluateS3Access(accessEvaluationInput{
			bucketARN:               testBucketARN,
			bucketPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
		})

		require.NoError(t, err)
		require.NotNil(t, accessControl)
		assert.Nil(t, accessControl.AllowPublicRead)
		require.NotNil(t, accessControl.PublicAccessBlock)
		require.NotNil(t, accessControl.PublicAccessBlock.Bucket)
		assert.Nil(t, accessControl.PublicAccessBlock.EffectiveAccount)
	})

	t.Run("malformed policy", func(t *testing.T) {
		t.Parallel()

		malformedPolicy := `{"Statement":`
		accessControl, err := evaluateS3Access(accessEvaluationInput{
			bucketARN:                testBucketARN,
			aclKnown:                 true,
			policyDocument:           &malformedPolicy,
			policyKnown:              true,
			bucketPublicAccessBlock:  knownPublicAccessBlock(false, false, false, false),
			accountPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
		})

		assert.Error(t, err)
		require.NotNil(t, accessControl)
		assert.Nil(t, accessControl.AllowPublicRead)
		assert.Nil(t, accessControl.AllowPublicWrite)
	})

	t.Run("unknown account block may suppress public access", func(t *testing.T) {
		t.Parallel()

		accessControl, err := evaluateS3Access(accessEvaluationInput{
			bucketARN:               testBucketARN,
			grants:                  []types.Grant{aclGrant(allUsersGroup, types.PermissionRead)},
			aclKnown:                true,
			policyKnown:             true,
			bucketPublicAccessBlock: knownPublicAccessBlock(false, false, false, false),
		})

		require.NoError(t, err)
		require.NotNil(t, accessControl)
		assert.Nil(t, accessControl.AllowPublicRead)
		assert.Nil(t, accessControl.IgnorePublicAcls)
	})
}

func TestEvaluateS3AccessRequiresBucketARN(t *testing.T) {
	t.Parallel()

	accessControl, err := evaluateS3Access(accessEvaluationInput{})

	assert.Error(t, err)
	assert.Nil(t, accessControl)
}

func aclGrant(groupURI string, permission types.Permission) types.Grant {
	return types.Grant{
		Grantee:    &types.Grantee{URI: aws.String(groupURI)},
		Permission: permission,
	}
}

func knownPublicAccessBlock(blockACLs, ignoreACLs, blockPolicy, restrictBuckets bool) publicAccessBlockState {
	return publicAccessBlockState{
		known: true,
		configuration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(blockACLs),
			IgnorePublicAcls:      aws.Bool(ignoreACLs),
			BlockPublicPolicy:     aws.Bool(blockPolicy),
			RestrictPublicBuckets: aws.Bool(restrictBuckets),
		},
	}
}

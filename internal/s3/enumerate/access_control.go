package enumerate

import (
	"fmt"

	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	allUsersGroup           = "http://acs.amazonaws.com/groups/global/AllUsers"
	authenticatedUsersGroup = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	logDeliveryGroup        = "http://acs.amazonaws.com/groups/s3/LogDelivery"
)

type publicAccessBlockState struct {
	configuration *types.PublicAccessBlockConfiguration
	known         bool
}

type accessEvaluationInput struct {
	bucketARN                string
	grants                   []types.Grant
	aclKnown                 bool
	policyDocument           *string
	policyKnown              bool
	bucketPublicAccessBlock  publicAccessBlockState
	accountPublicAccessBlock publicAccessBlockState
}

type aclPermissions struct {
	publicRead                    *bool
	publicWrite                   *bool
	publicReadACP                 *bool
	publicWriteACP                *bool
	publicFullControl             *bool
	authenticatedUsersRead        *bool
	authenticatedUsersWrite       *bool
	authenticatedUsersReadACP     *bool
	authenticatedUsersWriteACP    *bool
	authenticatedUsersFullControl *bool
	logDeliveryWrite              *bool
	logDeliveryReadACP            *bool
}

type effectivePublicAccessBlock struct {
	blockPublicACLs       *bool
	ignorePublicACLs      *bool
	blockPublicPolicy     *bool
	restrictPublicBuckets *bool
}

func evaluateS3Access(input accessEvaluationInput) (*s3fern.S3BucketAccessControl, error) {
	if err := validateAccessEvaluationInput(input); err != nil {
		return nil, err
	}
	acl := evaluateACLPermissions(input.grants, input.aclKnown)
	policy, policyErr := evaluatePolicyPermissions(input.policyDocument, input.policyKnown, input.bucketARN)
	publicAccessBlock := mergePublicAccessBlocks(input.bucketPublicAccessBlock, input.accountPublicAccessBlock)

	readACLBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.anonymousACLDenies.read)
	writeACLBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.anonymousACLDenies.write)
	readACPBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.anonymousACLDenies.readACP)
	writeACPBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.anonymousACLDenies.writeACP)
	fullControlBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.anonymousACLDenies.fullControl)
	authenticatedReadBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.authenticatedACLDenies.read)
	authenticatedWriteBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.authenticatedACLDenies.write)
	authenticatedReadACPBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.authenticatedACLDenies.readACP)
	authenticatedWriteACPBlocked := orDecisions(publicAccessBlock.ignorePublicACLs, policy.authenticatedACLDenies.writeACP)
	authenticatedFullControlBlocked := orDecisions(
		publicAccessBlock.ignorePublicACLs,
		policy.authenticatedACLDenies.fullControl,
	)

	acl.publicRead = blockedDecision(acl.publicRead, readACLBlocked)
	acl.publicWrite = blockedDecision(acl.publicWrite, writeACLBlocked)
	acl.publicReadACP = blockedDecision(acl.publicReadACP, readACPBlocked)
	acl.publicWriteACP = blockedDecision(acl.publicWriteACP, writeACPBlocked)
	acl.publicFullControl = blockedDecision(acl.publicFullControl, fullControlBlocked)
	acl.authenticatedUsersRead = blockedDecision(acl.authenticatedUsersRead, authenticatedReadBlocked)
	acl.authenticatedUsersWrite = blockedDecision(acl.authenticatedUsersWrite, authenticatedWriteBlocked)
	acl.authenticatedUsersReadACP = blockedDecision(acl.authenticatedUsersReadACP, authenticatedReadACPBlocked)
	acl.authenticatedUsersWriteACP = blockedDecision(acl.authenticatedUsersWriteACP, authenticatedWriteACPBlocked)
	acl.authenticatedUsersFullControl = blockedDecision(acl.authenticatedUsersFullControl, authenticatedFullControlBlocked)
	acl.logDeliveryWrite = blockedDecision(acl.logDeliveryWrite, policy.authenticatedACLDenies.write)
	acl.logDeliveryReadACP = blockedDecision(acl.logDeliveryReadACP, policy.authenticatedACLDenies.readACP)

	policy.publicRead = blockedDecision(policy.publicRead, publicAccessBlock.restrictPublicBuckets)
	policy.publicWrite = blockedDecision(policy.publicWrite, publicAccessBlock.restrictPublicBuckets)
	publicAccessBlockInfo := publicAccessBlockDetails(
		input.bucketPublicAccessBlock,
		input.accountPublicAccessBlock,
		publicAccessBlock,
	)

	accessControl := &s3fern.S3BucketAccessControl{
		AllowPublicRead:                    orDecisions(acl.publicRead, policy.publicRead),
		AllowPublicWrite:                   orDecisions(acl.publicWrite, policy.publicWrite),
		AllowPublicReadAcp:                 acl.publicReadACP,
		AllowPublicWriteAcp:                acl.publicWriteACP,
		AllowPublicFullControl:             acl.publicFullControl,
		AllowAuthenticatedUsersRead:        acl.authenticatedUsersRead,
		AllowAuthenticatedUsersWrite:       acl.authenticatedUsersWrite,
		AllowAuthenticatedUsersReadAcp:     acl.authenticatedUsersReadACP,
		AllowAuthenticatedUsersWriteAcp:    acl.authenticatedUsersWriteACP,
		AllowAuthenticatedUsersFullControl: acl.authenticatedUsersFullControl,
		AllowLogDeliveryWrite:              acl.logDeliveryWrite,
		AllowLogDeliveryReadAcp:            acl.logDeliveryReadACP,
		PublicAccessBlock:                  publicAccessBlockInfo,
		BlockPublicAcls:                    publicAccessBlock.blockPublicACLs,
		IgnorePublicAcls:                   publicAccessBlock.ignorePublicACLs,
		BlockPublicPolicy:                  publicAccessBlock.blockPublicPolicy,
		RestrictPublicBuckets:              publicAccessBlock.restrictPublicBuckets,
	}

	if !accessControlHasValues(accessControl) {
		return nil, policyErr
	}
	return accessControl, policyErr
}

func publicAccessBlockDetails(
	bucketState, accountState publicAccessBlockState,
	effective effectivePublicAccessBlock,
) *s3fern.S3PublicAccessBlock {
	bucket := publicAccessBlockConfiguration(bucketState)
	effectiveAccount := publicAccessBlockConfiguration(accountState)
	effectiveConfiguration := publicAccessBlockConfigurationFromValues(
		effective.blockPublicACLs,
		effective.ignorePublicACLs,
		effective.blockPublicPolicy,
		effective.restrictPublicBuckets,
	)
	if bucket == nil && effectiveAccount == nil && effectiveConfiguration == nil {
		return nil
	}
	return &s3fern.S3PublicAccessBlock{
		Bucket:           bucket,
		EffectiveAccount: effectiveAccount,
		Effective:        effectiveConfiguration,
	}
}

func publicAccessBlockConfiguration(state publicAccessBlockState) *s3fern.S3PublicAccessBlockConfiguration {
	if !state.known {
		return nil
	}
	if state.configuration == nil {
		return publicAccessBlockConfigurationFromValues(
			boolPointer(false),
			boolPointer(false),
			boolPointer(false),
			boolPointer(false),
		)
	}
	return publicAccessBlockConfigurationFromValues(
		state.configuration.BlockPublicAcls,
		state.configuration.IgnorePublicAcls,
		state.configuration.BlockPublicPolicy,
		state.configuration.RestrictPublicBuckets,
	)
}

func publicAccessBlockConfigurationFromValues(
	blockPublicACLs, ignorePublicACLs, blockPublicPolicy, restrictPublicBuckets *bool,
) *s3fern.S3PublicAccessBlockConfiguration {
	if blockPublicACLs == nil && ignorePublicACLs == nil && blockPublicPolicy == nil && restrictPublicBuckets == nil {
		return nil
	}
	return &s3fern.S3PublicAccessBlockConfiguration{
		BlockPublicAcls:       blockPublicACLs,
		IgnorePublicAcls:      ignorePublicACLs,
		BlockPublicPolicy:     blockPublicPolicy,
		RestrictPublicBuckets: restrictPublicBuckets,
	}
}

func evaluatePolicyPermissions(policyDocument *string, known bool, bucketARN string) (policyPermissions, error) {
	if !known {
		return policyPermissions{}, nil
	}
	if policyDocument == nil {
		return knownEmptyPolicyPermissions(), nil
	}
	permissions, err := analyzeBucketPolicy(*policyDocument, bucketARN)
	if err != nil {
		return policyPermissions{}, err
	}
	return permissions, nil
}

func knownEmptyPolicyPermissions() policyPermissions {
	return policyPermissions{
		publicRead:             boolPointer(false),
		publicWrite:            boolPointer(false),
		anonymousACLDenies:     knownEmptyACLPolicyDenies(),
		authenticatedACLDenies: knownEmptyACLPolicyDenies(),
	}
}

func knownEmptyACLPolicyDenies() aclPolicyDenies {
	return aclPolicyDenies{
		read:        boolPointer(false),
		write:       boolPointer(false),
		readACP:     boolPointer(false),
		writeACP:    boolPointer(false),
		fullControl: boolPointer(false),
	}
}

func evaluateACLPermissions(grants []types.Grant, known bool) aclPermissions {
	if !known {
		return aclPermissions{}
	}
	permissions := aclPermissions{
		publicRead:                    boolPointer(false),
		publicWrite:                   boolPointer(false),
		publicReadACP:                 boolPointer(false),
		publicWriteACP:                boolPointer(false),
		publicFullControl:             boolPointer(false),
		authenticatedUsersRead:        boolPointer(false),
		authenticatedUsersWrite:       boolPointer(false),
		authenticatedUsersReadACP:     boolPointer(false),
		authenticatedUsersWriteACP:    boolPointer(false),
		authenticatedUsersFullControl: boolPointer(false),
		logDeliveryWrite:              boolPointer(false),
		logDeliveryReadACP:            boolPointer(false),
	}

	for _, grant := range grants {
		if grant.Grantee == nil || grant.Grantee.URI == nil {
			continue
		}
		switch aws.ToString(grant.Grantee.URI) {
		case allUsersGroup:
			applyACLPermission(grant.Permission, &permissions.publicRead, &permissions.publicWrite,
				&permissions.publicReadACP, &permissions.publicWriteACP, &permissions.publicFullControl)
		case authenticatedUsersGroup:
			applyACLPermission(grant.Permission, &permissions.authenticatedUsersRead, &permissions.authenticatedUsersWrite,
				&permissions.authenticatedUsersReadACP, &permissions.authenticatedUsersWriteACP,
				&permissions.authenticatedUsersFullControl)
		case logDeliveryGroup:
			if grant.Permission == types.PermissionWrite || grant.Permission == types.PermissionFullControl {
				permissions.logDeliveryWrite = boolPointer(true)
			}
			if grant.Permission == types.PermissionReadAcp || grant.Permission == types.PermissionFullControl {
				permissions.logDeliveryReadACP = boolPointer(true)
			}
		}
	}
	return permissions
}

func applyACLPermission(permission types.Permission, read, write, readACP, writeACP, fullControl **bool) {
	switch permission {
	case types.PermissionRead:
		*read = boolPointer(true)
	case types.PermissionWrite:
		*write = boolPointer(true)
	case types.PermissionReadAcp:
		*readACP = boolPointer(true)
	case types.PermissionWriteAcp:
		*writeACP = boolPointer(true)
	case types.PermissionFullControl:
		*read = boolPointer(true)
		*write = boolPointer(true)
		*readACP = boolPointer(true)
		*writeACP = boolPointer(true)
		*fullControl = boolPointer(true)
	}
}

func mergePublicAccessBlocks(bucket, account publicAccessBlockState) effectivePublicAccessBlock {
	return effectivePublicAccessBlock{
		blockPublicACLs:       mergePublicAccessBlockValue(bucket, account, func(c *types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicAcls }),
		ignorePublicACLs:      mergePublicAccessBlockValue(bucket, account, func(c *types.PublicAccessBlockConfiguration) *bool { return c.IgnorePublicAcls }),
		blockPublicPolicy:     mergePublicAccessBlockValue(bucket, account, func(c *types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicPolicy }),
		restrictPublicBuckets: mergePublicAccessBlockValue(bucket, account, func(c *types.PublicAccessBlockConfiguration) *bool { return c.RestrictPublicBuckets }),
	}
}

func mergePublicAccessBlockValue(
	bucket, account publicAccessBlockState,
	value func(*types.PublicAccessBlockConfiguration) *bool,
) *bool {
	bucketValue := knownPublicAccessBlockValue(bucket, value)
	accountValue := knownPublicAccessBlockValue(account, value)
	return orDecisions(bucketValue, accountValue)
}

func knownPublicAccessBlockValue(
	state publicAccessBlockState,
	value func(*types.PublicAccessBlockConfiguration) *bool,
) *bool {
	if !state.known {
		return nil
	}
	if state.configuration == nil {
		return boolPointer(false)
	}
	return value(state.configuration)
}

func blockedDecision(decision, blocked *bool) *bool {
	if blocked != nil && *blocked {
		return boolPointer(false)
	}
	if decision == nil || blocked == nil {
		if decision != nil && !*decision {
			return boolPointer(false)
		}
		return nil
	}
	return decision
}

func orDecisions(decisions ...*bool) *bool {
	unknown := false
	for _, decision := range decisions {
		if decision == nil {
			unknown = true
			continue
		}
		if *decision {
			return boolPointer(true)
		}
	}
	if unknown {
		return nil
	}
	return boolPointer(false)
}

func accessControlHasValues(accessControl *s3fern.S3BucketAccessControl) bool {
	return accessControl.AllowPublicRead != nil || accessControl.AllowPublicWrite != nil ||
		accessControl.AllowPublicReadAcp != nil || accessControl.AllowPublicWriteAcp != nil ||
		accessControl.AllowPublicFullControl != nil || accessControl.AllowAuthenticatedUsersRead != nil ||
		accessControl.AllowAuthenticatedUsersWrite != nil || accessControl.AllowAuthenticatedUsersReadAcp != nil ||
		accessControl.AllowAuthenticatedUsersWriteAcp != nil || accessControl.AllowAuthenticatedUsersFullControl != nil ||
		accessControl.AllowLogDeliveryWrite != nil || accessControl.AllowLogDeliveryReadAcp != nil ||
		accessControl.PublicAccessBlock != nil ||
		accessControl.BlockPublicAcls != nil || accessControl.IgnorePublicAcls != nil ||
		accessControl.BlockPublicPolicy != nil || accessControl.RestrictPublicBuckets != nil
}

func validateAccessEvaluationInput(input accessEvaluationInput) error {
	if input.bucketARN == "" {
		return fmt.Errorf("bucket ARN is required for access evaluation")
	}
	return nil
}

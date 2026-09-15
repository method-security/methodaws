package s3

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBucketARN = "arn:aws:s3:::example-bucket"

func TestAnalyzeBucketPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      string
		publicRead  *bool
		publicWrite *bool
	}{
		{
			name: "public read with standard metadata",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "PublicRead",
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*"
				}]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "wildcard actions",
			policy: `{
				"Statement": {
					"Effect": "Allow",
					"Principal": {"AWS": "*"},
					"Action": ["s3:Get*", "s3:PutObject"],
					"Resource": "arn:aws:s3:::example-bucket/*"
				}
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(true),
		},
		{
			name: "public access to an object prefix",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": ["s3:GetObject", "s3:PutObject"],
					"Resource": "arn:aws:s3:::example-bucket/public/*"
				}]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(true),
		},
		{
			name: "policy variable resource is not guessed",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": ["s3:GetObject", "s3:PutObject"],
					"Resource": "arn:aws:s3:::example-bucket/${aws:username}/*"
				}]
			}`,
			publicRead:  nil,
			publicWrite: nil,
		},
		{
			name: "anonymous user ID policy variable is resolved",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/public/${aws:userid}/*"
				}]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "policy variable deny for another bucket does not affect public access",
			policy: `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::example-bucket/*"
						},
						{
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::different-bucket/${aws:username}/*"
						}
					]
				}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "deny on the same object prefix overrides public access",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/public/*"
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/public/*"
					}
				]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "deny on probe key does not hide a broader public prefix",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/public/*"
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/public/method-public-probe"
					}
				]
			}`,
			publicRead:  nil,
			publicWrite: boolPointer(false),
		},
		{
			name: "named AWS principal is not public",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "s3:*",
					"Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
				}]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "principal action and resource are evaluated in the same statement",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::different-bucket/*"
					},
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "explicit deny overrides public allow",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
					}
				]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "TLS enforcement deny preserves HTTPS public access",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:*",
						"Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"],
						"Condition": {"Bool": {"aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false"}}
					}
				]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "fixed source ARN restricts access",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:cloudfront::123456789012:distribution/ABC"}}
				}]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "unknown condition is not guessed",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"StringEquals": {"s3:ExistingObjectTag/public": "true"}}
				}]
			}`,
			publicRead:  nil,
			publicWrite: boolPointer(false),
		},
		{
			name: "wildcard trusted condition is not guessed",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:cloudfront::*:distribution/*"}}
				}]
			}`,
			publicRead:  nil,
			publicWrite: boolPointer(false),
		},
		{
			name: "malformed trusted condition is not guessed",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"StringEquals": {"aws:SourceAccount": true}}
				}]
			}`,
			publicRead:  nil,
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAllValues without Null remains public when the key is absent",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"ForAllValues:StringEquals": {"aws:SourceVpc": "vpc-12345678"}}
				}]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAnyValue negative allow requires the trusted key",
			policy: `{
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*",
						"Condition": {"ForAnyValue:StringNotEquals": {"aws:SourceVpc": "vpc-12345678"}}
					}]
				}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAnyValue negative deny does not apply when the key is absent",
			policy: `{
					"Statement": [
						{
							"Effect": "Allow",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::example-bucket/*"
						},
						{
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::example-bucket/*",
							"Condition": {"ForAnyValue:StringNotEquals": {"aws:SourceVpc": "vpc-12345678"}}
						}
					]
				}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAnyValue negative IfExists allow applies when the key is absent",
			policy: `{
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*",
						"Condition": {"ForAnyValue:StringNotEqualsIfExists": {"aws:SourceVpc": "vpc-12345678"}}
					}]
				}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAnyValue negative IfExists deny applies when the key is absent",
			policy: `{
					"Statement": [
						{
							"Effect": "Allow",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::example-bucket/*"
						},
						{
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:GetObject",
							"Resource": "arn:aws:s3:::example-bucket/*",
							"Condition": {"ForAnyValue:StringNotEqualsIfExists": {"aws:SourceVpc": "vpc-12345678"}}
						}
					]
				}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "positive IfExists allow applies when the key is absent",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-12345678"}}
				}]
			}`,
			publicRead:  boolPointer(true),
			publicWrite: boolPointer(false),
		},
		{
			name: "set-qualified positive IfExists deny applies when the key is absent",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*",
						"Condition": {"ForAnyValue:StringEqualsIfExists": {"aws:SourceVpc": "vpc-12345678"}}
					}
				]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "Null check makes ForAllValues require the trusted key",
			policy: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/*",
					"Condition": {
						"ForAllValues:StringEquals": {"aws:SourceVpc": "vpc-12345678"},
						"Null": {"aws:SourceVpc": "false"}
					}
				}]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
		{
			name: "ForAllValues deny applies when the key is absent",
			policy: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					},
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*",
						"Condition": {"ForAllValues:StringEquals": {"aws:SourceVpc": "vpc-12345678"}}
					}
				]
			}`,
			publicRead:  boolPointer(false),
			publicWrite: boolPointer(false),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			permissions, err := analyzeBucketPolicy(test.policy, testBucketARN)

			require.NoError(t, err)
			assert.Equal(t, test.publicRead, permissions.publicRead)
			assert.Equal(t, test.publicWrite, permissions.publicWrite)
		})
	}
}

func TestAnalyzeBucketPolicyRejectsMalformedOrEmptyPolicies(t *testing.T) {
	t.Parallel()

	for _, policy := range []string{`{"Statement":`, `{"Version":"2012-10-17"}`, `{"Statement":[]}`} {
		permissions, err := analyzeBucketPolicy(policy, testBucketARN)

		assert.Error(t, err)
		assert.Nil(t, permissions.publicRead)
		assert.Nil(t, permissions.publicWrite)
	}
}

func TestClassifyAllowConditionIsDeterministic(t *testing.T) {
	t.Parallel()

	condition := map[string]map[string]json.RawMessage{
		"StringEquals": {
			"aws:SourceVpc":             json.RawMessage(`"vpc-12345678"`),
			"s3:ExistingObjectTag/team": json.RawMessage(`"security"`),
		},
	}
	for range 1000 {
		assert.Equal(t, conditionRestricted, classifyAllowCondition(condition))
	}
}

func TestClassifySourceIPCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		operator string
		values   json.RawMessage
		expected conditionResult
	}{
		{name: "fixed IPv4 range", operator: "IpAddress", values: json.RawMessage(`"10.0.0.0/24"`), expected: conditionRestricted},
		{name: "fixed IPv6 range", operator: "IpAddress", values: json.RawMessage(`"fd00::/48"`), expected: conditionRestricted},
		{name: "broad IPv4 range", operator: "IpAddress", values: json.RawMessage(`"0.0.0.0/1"`), expected: conditionPublic},
		{name: "broad IPv6 range", operator: "IpAddress", values: json.RawMessage(`"::/0"`), expected: conditionPublic},
		{name: "negative match", operator: "NotIpAddress", values: json.RawMessage(`"10.0.0.0/24"`), expected: conditionPublic},
		{name: "negative match excludes all addresses", operator: "NotIpAddress", values: json.RawMessage(`["0.0.0.0/0", "::/0"]`), expected: conditionRestricted},
		{name: "negative match combines prefixes", operator: "NotIpAddress", values: json.RawMessage(`["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]`), expected: conditionRestricted},
		{name: "IfExists fixed range", operator: "IpAddressIfExists", values: json.RawMessage(`"10.0.0.0/24"`), expected: conditionRestricted},
		{name: "invalid range", operator: "IpAddress", values: json.RawMessage(`"invalid"`), expected: conditionUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.expected, classifySourceIPCondition(test.operator, test.values))
		})
	}
}

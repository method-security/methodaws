package enumerate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Method-Security/methodaws/generated/go/common"
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func configuredBucketResources(ctx context.Context, client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3BucketResourceInfo, []string) {
	resources := &s3fern.S3BucketResourceInfo{}
	var errs []string
	if bucket.Configuration.Policy != nil {
		resources.IamRolePolicyStatements, errs = policyRoleStatements(*bucket.Configuration.Policy)
		for i := range errs {
			errs[i] = fmt.Sprintf("bucket %s policy: %s", bucket.Identification.Name, errs[i])
		}
	}
	notifications, err := client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: aws.String(bucket.Identification.Name),
	})
	if err != nil {
		errs = append(errs, fmt.Sprintf("bucket %s notifications: %v", bucket.Identification.Name, err))
	} else if notifications == nil {
		errs = append(errs, fmt.Sprintf("bucket %s notifications: no response", bucket.Identification.Name))
	} else {
		for i, notification := range notifications.LambdaFunctionConfigurations {
			function, err := notificationFunctionReference(aws.ToString(notification.LambdaFunctionArn))
			if err != nil {
				errs = append(errs, fmt.Sprintf("bucket %s Lambda notification %d: %v", bucket.Identification.Name, i, err))
				continue
			}
			entry := &s3fern.S3LambdaNotification{Function: function, Id: notification.Id}
			valid := len(notification.Events) > 0
			for _, event := range notification.Events {
				if strings.TrimSpace(string(event)) == "" {
					valid = false
				}
				entry.Events = append(entry.Events, string(event))
			}
			if notification.Filter != nil && notification.Filter.Key != nil {
				for _, rule := range notification.Filter.Key.FilterRules {
					if rule.Name == "" || rule.Value == nil {
						valid = false
						continue
					}
					entry.FilterRules = append(entry.FilterRules, &s3fern.S3NotificationFilterRule{
						Name: string(rule.Name), Value: *rule.Value,
					})
				}
			}
			if !valid {
				errs = append(errs, fmt.Sprintf("bucket %s Lambda notification %d: missing events or malformed filter", bucket.Identification.Name, i))
				continue
			}
			resources.LambdaNotifications = append(resources.LambdaNotifications, entry)
		}
	}
	if len(resources.IamRolePolicyStatements) == 0 && len(resources.LambdaNotifications) == 0 {
		return nil, errs
	}
	return resources, errs
}

func notificationFunctionReference(value string) (*common.LambdaReference, error) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Partition == "" || parsed.Service != "lambda" || parsed.Region == "" ||
		!validReferenceAccount(parsed.AccountID) || strings.ContainsAny(value, "*?{ \t\r\n") {
		return nil, fmt.Errorf("missing or invalid Lambda function ARN %q", value)
	}
	parts := strings.Split(parsed.Resource, ":")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "function" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
		return nil, fmt.Errorf("invalid Lambda function ARN %q", value)
	}
	const functionCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	if strings.Trim(parts[1], functionCharacters) != "" ||
		(len(parts) == 3 && parts[2] != "$LATEST" && strings.Trim(parts[2], functionCharacters) != "") {
		return nil, fmt.Errorf("invalid Lambda function ARN %q", value)
	}
	return &common.LambdaReference{Arn: value, Region: parsed.Region, FunctionName: &parts[1]}, nil
}

func policyRoleStatements(document string) ([]*s3fern.S3IamRolePolicyStatement, []string) {
	var rawDocument struct {
		Statements json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &rawDocument); err != nil {
		return nil, []string{fmt.Sprintf("parse document: %v", err)}
	}
	data := bytes.TrimSpace(rawDocument.Statements)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, []string{"missing Statement"}
	}
	var statements []json.RawMessage
	if data[0] == '[' {
		if err := json.Unmarshal(data, &statements); err != nil {
			return nil, []string{fmt.Sprintf("parse statements: %v", err)}
		}
	} else {
		statements = []json.RawMessage{data}
	}
	var result []*s3fern.S3IamRolePolicyStatement
	var errs []string
	for i, raw := range statements {
		var statement policyStatement
		if err := json.Unmarshal(raw, &statement); err != nil {
			errs = append(errs, fmt.Sprintf("statement %d: %v", i, err))
			continue
		}
		entry := &s3fern.S3IamRolePolicyStatement{Statement: string(raw)}
		for _, source := range []struct {
			name   string
			raw    json.RawMessage
			target *[]*s3fern.S3PolicyRoleReference
		}{
			{"Principal", statement.Principal, &entry.PrincipalRoles},
			{"NotPrincipal", statement.NotPrincipal, &entry.NotPrincipalRoles},
		} {
			var principals map[string]json.RawMessage
			if len(source.raw) == 0 || bytes.Equal(bytes.TrimSpace(source.raw), []byte(`"*"`)) {
				continue
			}
			if err := json.Unmarshal(source.raw, &principals); err != nil {
				errs = append(errs, fmt.Sprintf("statement %d %s: %v", i, source.name, err))
				continue
			}
			if values, exists := principals["AWS"]; exists {
				refs, refErrors := policyRoleReferences(values)
				*source.target = refs
				for _, err := range refErrors {
					errs = append(errs, fmt.Sprintf("statement %d %s: %s", i, source.name, err))
				}
			}
		}
		operators := make([]string, 0, len(statement.Condition))
		for operator := range statement.Condition {
			operators = append(operators, operator)
		}
		sort.Strings(operators)
		for _, operator := range operators {
			for key, values := range statement.Condition[operator] {
				if !strings.EqualFold(key, "aws:PrincipalArn") {
					continue
				}
				refs, refErrors := policyRoleReferences(values)
				entry.ConditionRoles = append(entry.ConditionRoles, refs...)
				for _, err := range refErrors {
					errs = append(errs, fmt.Sprintf("statement %d condition %s: %s", i, operator, err))
				}
			}
		}
		if len(entry.PrincipalRoles)+len(entry.NotPrincipalRoles)+len(entry.ConditionRoles) > 0 {
			result = append(result, entry)
		}
	}
	return result, errs
}

func policyRoleReferences(raw json.RawMessage) ([]*s3fern.S3PolicyRoleReference, []string) {
	var values stringList
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, []string{err.Error()}
	}
	var result []*s3fern.S3PolicyRoleReference
	var errs []string
	seen := make(map[string]bool)
	for _, value := range values {
		// Wildcards and variables describe sets of principals, not concrete role IDs.
		if strings.ContainsAny(value, "*?${") || !strings.Contains(value, ":role/") {
			continue
		}
		parsed, err := arn.Parse(value)
		if err != nil || parsed.Partition == "" || parsed.Service != "iam" || parsed.Region != "" ||
			!validReferenceAccount(parsed.AccountID) || !strings.HasPrefix(parsed.Resource, "role/") ||
			strings.HasSuffix(parsed.Resource, "/") || strings.ContainsAny(value, " \t\r\n") {
			errs = append(errs, fmt.Sprintf("invalid IAM role ARN %q", value))
			continue
		}
		if !seen[value] {
			name := parsed.Resource[strings.LastIndex(parsed.Resource, "/")+1:]
			if strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+=,.@-") != "" {
				errs = append(errs, fmt.Sprintf("invalid IAM role ARN %q", value))
				continue
			}
			result = append(result, &s3fern.S3PolicyRoleReference{Arn: value, RoleName: &name})
			seen[value] = true
		}
	}
	return result, errs
}

func validReferenceAccount(account string) bool {
	return len(account) == 12 && strings.Trim(account, "0123456789") == ""
}

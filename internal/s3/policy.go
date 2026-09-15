package s3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type policyPermissions struct {
	publicRead         *bool
	publicWrite        *bool
	denyACLRead        *bool
	denyACLWrite       *bool
	denyACLReadACP     *bool
	denyACLWriteACP    *bool
	denyACLFullControl *bool
}

type policyDocument struct {
	Statements policyStatements `json:"Statement"`
}

type policyStatements []policyStatement

func (s *policyStatements) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return fmt.Errorf("policy Statement cannot be empty")
	}
	if data[0] == '[' {
		return json.Unmarshal(data, (*[]policyStatement)(s))
	}
	var statement policyStatement
	if err := json.Unmarshal(data, &statement); err != nil {
		return err
	}
	*s = []policyStatement{statement}
	return nil
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("expected a string or list of strings: %w", err)
	}
	*s = multiple
	return nil
}

type policyStatement struct {
	Effect       string                                `json:"Effect"`
	Principal    json.RawMessage                       `json:"Principal"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal"`
	Action       stringList                            `json:"Action"`
	NotAction    stringList                            `json:"NotAction"`
	Resource     stringList                            `json:"Resource"`
	NotResource  stringList                            `json:"NotResource"`
	Condition    map[string]map[string]json.RawMessage `json:"Condition"`
}

type policyOperation struct {
	action   string
	resource string
}

var publicReadOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:GetObject", resource: bucketARN + "/object"}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:GetObjectVersion", resource: bucketARN + "/object"}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:ListBucket", resource: bucketARN}
	},
}

var publicWriteOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:PutObject", resource: bucketARN + "/object"}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:DeleteObject", resource: bucketARN + "/object"}
	},
}

var aclReadOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:ListBucket", resource: bucketARN}
	},
}

var aclWriteOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:PutObject", resource: bucketARN + "/object"}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:DeleteObject", resource: bucketARN + "/object"}
	},
}

var aclReadACPOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:GetBucketAcl", resource: bucketARN}
	},
}

var aclWriteACPOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:PutBucketAcl", resource: bucketARN}
	},
}

func analyzeBucketPolicy(policyJSON, bucketARN string) (policyPermissions, error) {
	var document policyDocument
	if err := json.Unmarshal([]byte(policyJSON), &document); err != nil {
		return policyPermissions{}, fmt.Errorf("parse S3 bucket policy: %w", err)
	}
	if len(document.Statements) == 0 {
		return policyPermissions{}, fmt.Errorf("parse S3 bucket policy: Statement cannot be empty")
	}

	return policyPermissions{
		publicRead:         evaluatePolicyCapability(document.Statements, bucketARN, publicReadOperations),
		publicWrite:        evaluatePolicyCapability(document.Statements, bucketARN, publicWriteOperations),
		denyACLRead:        evaluatePolicyDenyCapability(document.Statements, bucketARN, aclReadOperations),
		denyACLWrite:       evaluatePolicyDenyCapability(document.Statements, bucketARN, aclWriteOperations),
		denyACLReadACP:     evaluatePolicyDenyCapability(document.Statements, bucketARN, aclReadACPOperations),
		denyACLWriteACP:    evaluatePolicyDenyCapability(document.Statements, bucketARN, aclWriteACPOperations),
		denyACLFullControl: evaluateAnyPolicyDeny(document.Statements, bucketARN),
	}, nil
}

func evaluatePolicyDenyCapability(
	statements []policyStatement,
	bucketARN string,
	operations []func(string) policyOperation,
) *bool {
	unknown := false
	for _, operationForBucket := range operations {
		denied := evaluatePolicyOperationDeny(statements, operationForBucket(bucketARN))
		if denied != nil && !*denied {
			return boolPointer(false)
		}
		if denied == nil {
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	return boolPointer(true)
}

func evaluateAnyPolicyDeny(statements []policyStatement, bucketARN string) *bool {
	unknown := false
	operationGroups := [][]func(string) policyOperation{
		aclReadOperations,
		aclWriteOperations,
		aclReadACPOperations,
		aclWriteACPOperations,
	}
	for _, operations := range operationGroups {
		for _, operationForBucket := range operations {
			denied := evaluatePolicyOperationDeny(statements, operationForBucket(bucketARN))
			if denied != nil && *denied {
				return boolPointer(true)
			}
			if denied == nil {
				unknown = true
			}
		}
	}
	if unknown {
		return nil
	}
	return boolPointer(false)
}

func evaluatePolicyOperationDeny(statements []policyStatement, operation policyOperation) *bool {
	unknown := false
	for _, statement := range statements {
		if !strings.EqualFold(statement.Effect, "Deny") {
			continue
		}
		principal := statementPublicPrincipal(statement)
		action := valuesMatch(statement.Action, statement.NotAction, operation.action, true)
		resource := valuesMatch(statement.Resource, statement.NotResource, operation.resource, false)
		if principal == matchNo || action == matchNo || resource == matchNo {
			continue
		}
		if principal == matchUnknown || action == matchUnknown || resource == matchUnknown {
			unknown = true
			continue
		}
		if len(statement.Condition) == 0 {
			return boolPointer(true)
		}
		switch classifyDenyCondition(statement.Condition) {
		case denyBlocksPublic:
			return boolPointer(true)
		case denyUnknown:
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	return boolPointer(false)
}

func evaluatePolicyCapability(
	statements []policyStatement,
	bucketARN string,
	operations []func(string) policyOperation,
) *bool {
	unknown := false
	for _, operationForBucket := range operations {
		operation := operationForBucket(bucketARN)
		for _, resource := range policyOperationResources(statements, bucketARN, operation) {
			operation.resource = resource
			decision := evaluatePolicyOperation(statements, operation)
			if decision != nil && *decision {
				return boolPointer(true)
			}
			if decision == nil {
				unknown = true
			}
		}
	}
	if unknown {
		return nil
	}
	return boolPointer(false)
}

func policyOperationResources(
	statements []policyStatement,
	bucketARN string,
	operation policyOperation,
) []string {
	resources := []string{operation.resource}
	if !strings.HasPrefix(operation.resource, bucketARN+"/") {
		return resources
	}

	seen := map[string]struct{}{operation.resource: {}}
	for _, statement := range statements {
		if !strings.EqualFold(statement.Effect, "Allow") ||
			statementPublicPrincipal(statement) == matchNo ||
			valuesMatch(statement.Action, statement.NotAction, operation.action, true) == matchNo {
			continue
		}
		for _, resourcePattern := range statement.Resource {
			resource, ok := objectResourceProbe(resourcePattern, bucketARN)
			if !ok {
				continue
			}
			if _, exists := seen[resource]; exists {
				continue
			}
			seen[resource] = struct{}{}
			resources = append(resources, resource)
		}
	}
	return resources
}

func objectResourceProbe(resourcePattern, bucketARN string) (string, bool) {
	if strings.Contains(resourcePattern, "${") {
		return "", false
	}
	separator := strings.Index(resourcePattern, "/")
	if separator < 0 || !wildcardMatch(resourcePattern[:separator], bucketARN, false) {
		return "", false
	}

	objectPattern := resourcePattern[separator+1:]
	if objectPattern == "" {
		return "", false
	}
	objectKey := strings.NewReplacer("*", "method-public-probe", "?", "x").Replace(objectPattern)
	resource := bucketARN + "/" + objectKey
	return resource, wildcardMatch(resourcePattern, resource, false)
}

func evaluatePolicyOperation(statements []policyStatement, operation policyOperation) *bool {
	allowed := false
	unknownAllow := false
	unknownDeny := false

	for _, statement := range statements {
		principal := statementPublicPrincipal(statement)
		if principal == matchNo {
			continue
		}
		action := valuesMatch(statement.Action, statement.NotAction, operation.action, true)
		resource := valuesMatch(statement.Resource, statement.NotResource, operation.resource, false)
		if action == matchNo || resource == matchNo {
			continue
		}
		if principal == matchUnknown || action == matchUnknown || resource == matchUnknown {
			if strings.EqualFold(statement.Effect, "Deny") {
				unknownDeny = true
			} else {
				unknownAllow = true
			}
			continue
		}

		switch {
		case strings.EqualFold(statement.Effect, "Allow"):
			switch classifyAllowCondition(statement.Condition) {
			case conditionPublic:
				allowed = true
			case conditionUnknown:
				unknownAllow = true
			}
		case strings.EqualFold(statement.Effect, "Deny"):
			switch classifyDenyCondition(statement.Condition) {
			case denyBlocksPublic:
				return boolPointer(false)
			case denyUnknown:
				unknownDeny = true
			}
		default:
			unknownAllow = true
		}
	}

	if allowed && !unknownDeny {
		return boolPointer(true)
	}
	if unknownAllow || unknownDeny {
		return nil
	}
	return boolPointer(false)
}

type matchResult uint8

const (
	matchNo matchResult = iota
	matchYes
	matchUnknown
)

func statementPublicPrincipal(statement policyStatement) matchResult {
	if len(statement.NotPrincipal) > 0 {
		return matchUnknown
	}
	if len(statement.Principal) == 0 {
		return matchUnknown
	}

	var principalString string
	if err := json.Unmarshal(statement.Principal, &principalString); err == nil {
		if principalString == "*" {
			return matchYes
		}
		return matchNo
	}

	var principalMap map[string]json.RawMessage
	if err := json.Unmarshal(statement.Principal, &principalMap); err != nil {
		return matchUnknown
	}
	for principalType, rawValues := range principalMap {
		if !strings.EqualFold(principalType, "AWS") {
			continue
		}
		values, err := decodeStringList(rawValues)
		if err != nil {
			return matchUnknown
		}
		for _, value := range values {
			if value == "*" {
				return matchYes
			}
		}
	}
	return matchNo
}

func valuesMatch(values, excludedValues []string, candidate string, caseInsensitive bool) matchResult {
	if len(excludedValues) > 0 || len(values) == 0 {
		return matchUnknown
	}
	unknown := false
	for _, value := range values {
		if strings.Contains(value, "${") {
			if policyVariablePatternCouldMatch(value, candidate, caseInsensitive) {
				unknown = true
			}
			continue
		}
		if wildcardMatch(value, candidate, caseInsensitive) {
			return matchYes
		}
	}
	if unknown {
		return matchUnknown
	}
	return matchNo
}

func policyVariablePatternCouldMatch(pattern, candidate string, caseInsensitive bool) bool {
	variableStart := strings.Index(pattern, "${")
	return variableStart >= 0 && wildcardMatch(pattern[:variableStart]+"*", candidate, caseInsensitive)
}

func wildcardMatch(pattern, value string, caseInsensitive bool) bool {
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, `\*`, `.*`)
	expression = strings.ReplaceAll(expression, `\?`, `.`)
	matched, err := regexp.MatchString("^"+expression+"$", value)
	return err == nil && matched
}

type conditionResult uint8

const (
	conditionRestricted conditionResult = iota
	conditionPublic
	conditionUnknown
)

var trustedConditionKeys = map[string]struct{}{
	"aws:principalaccount":      {},
	"aws:principalarn":          {},
	"aws:principalorgid":        {},
	"aws:sourceaccount":         {},
	"aws:sourcearn":             {},
	"aws:sourceowner":           {},
	"aws:sourcevpc":             {},
	"aws:sourcevpce":            {},
	"s3:dataaccesspointaccount": {},
	"s3:dataaccesspointarn":     {},
}

var publicConditionKeys = map[string]struct{}{
	"aws:referer":         {},
	"aws:securetransport": {},
	"aws:useragent":       {},
	"s3:tlsversion":       {},
}

func classifyAllowCondition(condition map[string]map[string]json.RawMessage) conditionResult {
	if len(condition) == 0 {
		return conditionPublic
	}
	result := conditionPublic
	for operator, entries := range condition {
		for key, rawValues := range entries {
			switch classifyAllowConditionEntry(operator, key, rawValues) {
			case conditionRestricted:
				// Conditions are ANDed, so one fixed trust boundary proves the grant is not public.
				return conditionRestricted
			case conditionUnknown:
				result = conditionUnknown
			}
		}
	}
	return result
}

func classifyAllowConditionEntry(operator, key string, rawValues json.RawMessage) conditionResult {
	normalizedKey := strings.ToLower(key)
	if normalizedKey == "aws:sourceip" {
		return classifySourceIPCondition(operator, rawValues)
	}
	if _, ok := trustedConditionKeys[normalizedKey]; ok {
		if isForAllValuesPositiveOperator(operator) {
			// ForAllValues is true for a missing request key unless a separate Null condition requires it.
			return conditionPublic
		}
		if strings.EqualFold(operator, "Null") {
			values, err := decodeStringList(rawValues)
			if err != nil || len(values) != 1 {
				return conditionUnknown
			}
			if strings.EqualFold(values[0], "false") {
				return conditionRestricted
			}
			return conditionPublic
		}
		if isPositiveConditionOperator(operator) {
			fixed, err := conditionValuesAreFixed(rawValues)
			if err != nil || !fixed {
				return conditionUnknown
			}
			return conditionRestricted
		}
		if isForAnyValuesNegativeOperator(operator) {
			return conditionRestricted
		}
		if isNegativeConditionOperator(operator) {
			return conditionPublic
		}
		return conditionUnknown
	}
	if _, ok := publicConditionKeys[normalizedKey]; ok {
		return conditionPublic
	}
	return conditionUnknown
}

func classifySourceIPCondition(operator string, rawValues json.RawMessage) conditionResult {
	values, err := decodeStringList(rawValues)
	if err != nil || len(values) == 0 {
		return conditionUnknown
	}
	if strings.EqualFold(operator, "NotIpAddress") {
		return conditionPublic
	}
	if !strings.EqualFold(operator, "IpAddress") {
		return conditionUnknown
	}

	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return conditionUnknown
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 32) {
			return conditionPublic
		}
	}
	return conditionRestricted
}

func isPositiveConditionOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "foranyvalue:")
	return operator == "stringequals" || operator == "arnequals" || operator == "stringlike" || operator == "arnlike"
}

func isForAllValuesPositiveOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if !strings.HasPrefix(operator, "forallvalues:") || strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "forallvalues:")
	return operator == "stringequals" || operator == "arnequals" || operator == "stringlike" || operator == "arnlike"
}

func isNegativeConditionOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if strings.HasPrefix(operator, "foranyvalue:") && !strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "foranyvalue:")
	operator = strings.TrimPrefix(operator, "forallvalues:")
	operator = strings.TrimSuffix(operator, "ifexists")
	return operator == "stringnotequals" || operator == "arnnotequals" ||
		operator == "stringnotlike" || operator == "arnnotlike"
}

func isForAnyValuesNegativeOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if !strings.HasPrefix(operator, "foranyvalue:") || strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "foranyvalue:")
	return operator == "stringnotequals" || operator == "arnnotequals" ||
		operator == "stringnotlike" || operator == "arnnotlike"
}

func conditionValuesAreFixed(rawValues json.RawMessage) (bool, error) {
	values, err := decodeStringList(rawValues)
	if err != nil {
		return false, err
	}
	if len(values) == 0 {
		return false, nil
	}
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "*?") || strings.Contains(value, "${") {
			return false, nil
		}
	}
	return true, nil
}

func isTransportOnlyDeny(condition map[string]map[string]json.RawMessage) bool {
	if len(condition) != 1 {
		return false
	}
	for operator, entries := range condition {
		if !strings.EqualFold(operator, "Bool") || len(entries) < 1 || len(entries) > 2 {
			return false
		}
		secureTransportFound := false
		for key, rawValue := range entries {
			if !strings.EqualFold(key, "aws:SecureTransport") &&
				!strings.EqualFold(key, "aws:PrincipalIsAWSService") {
				return false
			}
			values, err := decodeStringList(rawValue)
			if err != nil || len(values) != 1 || !strings.EqualFold(values[0], "false") {
				return false
			}
			secureTransportFound = secureTransportFound || strings.EqualFold(key, "aws:SecureTransport")
		}
		return secureTransportFound
	}
	return false
}

type denyConditionResult uint8

const (
	denyDoesNotBlockPublic denyConditionResult = iota
	denyBlocksPublic
	denyUnknown
)

func classifyDenyCondition(condition map[string]map[string]json.RawMessage) denyConditionResult {
	if len(condition) == 0 {
		return denyBlocksPublic
	}
	if isTransportOnlyDeny(condition) {
		return denyDoesNotBlockPublic
	}
	if len(condition) != 1 {
		return denyUnknown
	}
	for operator, entries := range condition {
		if len(entries) != 1 {
			return denyUnknown
		}
		for key, rawValues := range entries {
			if _, ok := trustedConditionKeys[strings.ToLower(key)]; !ok {
				return denyUnknown
			}
			fixed, err := conditionValuesAreFixed(rawValues)
			if err != nil || !fixed {
				return denyUnknown
			}
			if isForAnyValuesNegativeOperator(operator) {
				return denyDoesNotBlockPublic
			}
			if isNegativeConditionOperator(operator) {
				return denyBlocksPublic
			}
			if isForAllValuesPositiveOperator(operator) {
				return denyBlocksPublic
			}
			if isPositiveConditionOperator(operator) {
				return denyDoesNotBlockPublic
			}
		}
	}
	return denyUnknown
}

func decodeStringList(data []byte) ([]string, error) {
	var values stringList
	if err := values.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return values, nil
}

func boolPointer(value bool) *bool {
	return &value
}

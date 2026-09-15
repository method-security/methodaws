package enumerate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type policyPermissions struct {
	publicRead             *bool
	publicWrite            *bool
	anonymousACLDenies     aclPolicyDenies
	authenticatedACLDenies aclPolicyDenies
}

// Public S3 endpoints support TLS 1.3, so minimum-version denies at or below this floor retain an allowed TLS path.
const knownPublicS3TLSVersion = 1.3

type aclPolicyDenies struct {
	read        *bool
	write       *bool
	readACP     *bool
	writeACP    *bool
	fullControl *bool
}

type policyPrincipalKind uint8

const (
	policyPrincipalAnonymous policyPrincipalKind = iota
	policyPrincipalAuthenticated
)

type policyDocument struct {
	Version    string           `json:"Version"`
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
	action                 string
	resource               string
	resourceIsScope        bool
	allowedResourcePattern string
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
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:ListBucketVersions", resource: bucketARN}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:ListBucketMultipartUploads", resource: bucketARN}
	},
}

var aclWriteOperations = []func(string) policyOperation{
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:PutObject", resource: bucketARN + "/*", resourceIsScope: true}
	},
	func(bucketARN string) policyOperation {
		return policyOperation{action: "s3:DeleteObject", resource: bucketARN + "/*", resourceIsScope: true}
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
	resolveAnonymousPolicyVariables(document.Statements, document.Version)

	return policyPermissions{
		publicRead:             evaluatePolicyCapability(document.Statements, bucketARN, publicReadOperations),
		publicWrite:            evaluatePolicyCapability(document.Statements, bucketARN, publicWriteOperations),
		anonymousACLDenies:     evaluateACLPolicyDenies(document.Statements, bucketARN, policyPrincipalAnonymous),
		authenticatedACLDenies: evaluateACLPolicyDenies(document.Statements, bucketARN, policyPrincipalAuthenticated),
	}, nil
}

func evaluateACLPolicyDenies(
	statements []policyStatement,
	bucketARN string,
	principalKind policyPrincipalKind,
) aclPolicyDenies {
	return aclPolicyDenies{
		read:        evaluatePolicyDenyCapability(statements, bucketARN, aclReadOperations, principalKind),
		write:       evaluatePolicyDenyCapability(statements, bucketARN, aclWriteOperations, principalKind),
		readACP:     evaluatePolicyDenyCapability(statements, bucketARN, aclReadACPOperations, principalKind),
		writeACP:    evaluatePolicyDenyCapability(statements, bucketARN, aclWriteACPOperations, principalKind),
		fullControl: evaluateAnyPolicyDeny(statements, bucketARN, principalKind),
	}
}

func evaluatePolicyDenyCapability(
	statements []policyStatement,
	bucketARN string,
	operations []func(string) policyOperation,
	principalKind policyPrincipalKind,
) *bool {
	unknown := false
	for _, operationForBucket := range operations {
		denied := evaluatePolicyOperationDeny(statements, operationForBucket(bucketARN), principalKind)
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

func evaluateAnyPolicyDeny(statements []policyStatement, bucketARN string, principalKind policyPrincipalKind) *bool {
	unknown := false
	operationGroups := [][]func(string) policyOperation{
		aclReadOperations,
		aclWriteOperations,
		aclReadACPOperations,
		aclWriteACPOperations,
	}
	for _, operations := range operationGroups {
		for _, operationForBucket := range operations {
			denied := evaluatePolicyOperationDeny(statements, operationForBucket(bucketARN), principalKind)
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

func evaluatePolicyOperationDeny(
	statements []policyStatement,
	operation policyOperation,
	principalKind policyPrincipalKind,
) *bool {
	unknown := false
	for _, statement := range statements {
		if !strings.EqualFold(statement.Effect, "Deny") {
			continue
		}
		principal := statementPublicPrincipal(statement)
		action := valuesMatch(statement.Action, statement.NotAction, operation.action, true)
		resource := valuesMatch(statement.Resource, statement.NotResource, operation.resource, false)
		if operation.resourceIsScope {
			resource = valuesCoverResourceScope(statement.Resource, statement.NotResource, operation.resource)
		}
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
		switch classifyDenyCondition(statement.Condition, principalKind) {
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

func valuesCoverResourceScope(values, excludedValues []string, resourceScope string) matchResult {
	if len(excludedValues) > 0 || len(values) == 0 {
		return matchUnknown
	}

	unknown := false
	probe := strings.TrimSuffix(resourceScope, "*") + "method-public-probe"
	for _, value := range values {
		if value == "*" || value == resourceScope {
			return matchYes
		}
		if strings.ContainsAny(value, "*?") || strings.Contains(value, "${") {
			if policyVariablePatternCouldMatch(value, probe, false) || wildcardMatch(value, probe, false) {
				unknown = true
			}
		}
	}
	if unknown {
		return matchUnknown
	}
	return matchNo
}

func evaluatePolicyCapability(
	statements []policyStatement,
	bucketARN string,
	operations []func(string) policyOperation,
) *bool {
	unknown := false
	for _, operationForBucket := range operations {
		operation := operationForBucket(bucketARN)
		for _, resourceOperation := range policyOperationResources(statements, bucketARN, operation) {
			decision := evaluatePolicyOperation(statements, resourceOperation)
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
) []policyOperation {
	resources := []policyOperation{operation}
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
			resources = append(resources, policyOperation{
				action:                 operation.action,
				resource:               resource,
				allowedResourcePattern: resourcePattern,
			})
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
			if operation.allowedResourcePattern != "" &&
				!denyCoversAllowedResource(statement, operation.allowedResourcePattern) {
				unknownDeny = true
				continue
			}
			switch classifyDenyCondition(statement.Condition, policyPrincipalAnonymous) {
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

func denyCoversAllowedResource(statement policyStatement, allowedResourcePattern string) bool {
	if len(statement.NotResource) > 0 {
		return false
	}
	for _, deniedResourcePattern := range statement.Resource {
		if deniedResourcePattern == "*" || deniedResourcePattern == allowedResourcePattern ||
			trailingWildcardPatternCovers(deniedResourcePattern, allowedResourcePattern) {
			return true
		}
	}
	return false
}

func trailingWildcardPatternCovers(coveringPattern, coveredPattern string) bool {
	if !strings.HasSuffix(coveringPattern, "*") {
		return false
	}
	prefix := strings.TrimSuffix(coveringPattern, "*")
	return !strings.ContainsAny(prefix, "*?") && strings.HasPrefix(coveredPattern, prefix)
}

var anonymousUserIDVariable = regexp.MustCompile(`(?i)\$\{aws:userid\}`)

func resolveAnonymousPolicyVariables(statements []policyStatement, version string) {
	if version != "2012-10-17" {
		return
	}
	for index := range statements {
		for resourceIndex := range statements[index].Resource {
			statements[index].Resource[resourceIndex] = anonymousUserIDVariable.ReplaceAllString(
				statements[index].Resource[resourceIndex],
				"anonymous",
			)
		}
		for resourceIndex := range statements[index].NotResource {
			statements[index].NotResource[resourceIndex] = anonymousUserIDVariable.ReplaceAllString(
				statements[index].NotResource[resourceIndex],
				"anonymous",
			)
		}
	}
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
	if normalizedKey == "aws:principalaccount" {
		return classifyKnownConditionValue(operator, rawValues, "anonymous")
	}
	if _, ok := trustedConditionKeys[normalizedKey]; ok {
		if isPositiveIfExistsOperator(operator) {
			// IfExists makes the condition true when an anonymous request omits the key.
			return conditionPublic
		}
		if isForAllValuesPositiveOperator(operator) {
			// ForAllValues is true for a missing request key unless a separate Null condition requires it.
			return conditionPublic
		}
		if strings.EqualFold(operator, "Null") {
			values, err := decodeStringList(rawValues)
			if err != nil || len(values) != 1 {
				return conditionUnknown
			}
			switch {
			case strings.EqualFold(values[0], "false"):
				return conditionRestricted
			case strings.EqualFold(values[0], "true"):
				return conditionPublic
			default:
				return conditionUnknown
			}
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

func classifyKnownConditionValue(operator string, rawValues json.RawMessage, value string) conditionResult {
	values, err := decodeStringList(rawValues)
	if err != nil || len(values) == 0 {
		return conditionUnknown
	}
	if strings.EqualFold(operator, "Null") {
		if len(values) != 1 {
			return conditionUnknown
		}
		switch {
		case strings.EqualFold(values[0], "false"):
			return conditionPublic
		case strings.EqualFold(values[0], "true"):
			return conditionRestricted
		default:
			return conditionUnknown
		}
	}
	normalizedOperator := strings.ToLower(operator)
	normalizedOperator = strings.TrimPrefix(normalizedOperator, "foranyvalue:")
	normalizedOperator = strings.TrimPrefix(normalizedOperator, "forallvalues:")
	normalizedOperator = strings.TrimSuffix(normalizedOperator, "ifexists")

	matches := false
	for _, candidate := range values {
		switch normalizedOperator {
		case "stringequals", "arnequals", "stringnotequals", "arnnotequals":
			matches = candidate == value
		case "stringlike", "arnlike", "stringnotlike", "arnnotlike":
			matches = wildcardMatch(candidate, value, false)
		}
		if matches {
			break
		}
	}
	switch normalizedOperator {
	case "stringequals", "arnequals", "stringlike", "arnlike":
		if matches {
			return conditionPublic
		}
		return conditionRestricted
	case "stringnotequals", "arnnotequals", "stringnotlike", "arnnotlike":
		if matches {
			return conditionRestricted
		}
		return conditionPublic
	default:
		return conditionUnknown
	}
}

func classifySourceIPCondition(operator string, rawValues json.RawMessage) conditionResult {
	values, err := decodeStringList(rawValues)
	if err != nil || len(values) == 0 {
		return conditionUnknown
	}
	normalizedOperator := strings.ToLower(operator)
	normalizedOperator = strings.TrimSuffix(normalizedOperator, "ifexists")
	if normalizedOperator != "ipaddress" && normalizedOperator != "notipaddress" {
		return conditionUnknown
	}

	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return conditionUnknown
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	if normalizedOperator == "notipaddress" {
		if prefixesCoverAddressFamily(prefixes, true) && prefixesCoverAddressFamily(prefixes, false) {
			return conditionRestricted
		}
		return conditionPublic
	}

	for _, prefix := range prefixes {
		if (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 32) {
			return conditionPublic
		}
	}
	return conditionRestricted
}

type prefixCoverageNode struct {
	covered  bool
	children [2]*prefixCoverageNode
}

func prefixesCoverAddressFamily(prefixes []netip.Prefix, ipv4 bool) bool {
	root := &prefixCoverageNode{}
	bitLength := 128
	if ipv4 {
		bitLength = 32
	}
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() != ipv4 {
			continue
		}
		insertCoveredPrefix(root, prefix.Addr(), prefix.Bits(), bitLength)
	}
	return root.covered
}

func insertCoveredPrefix(node *prefixCoverageNode, address netip.Addr, prefixBits, bitLength int) {
	current := node
	for bitIndex := 0; bitIndex < prefixBits; bitIndex++ {
		if current.covered {
			return
		}
		bit := addressBit(address, bitIndex)
		if current.children[bit] == nil {
			current.children[bit] = &prefixCoverageNode{}
		}
		current = current.children[bit]
	}
	current.covered = true
	current.children = [2]*prefixCoverageNode{}
	collapseCoveredPrefixes(node, bitLength)
}

func addressBit(address netip.Addr, bitIndex int) int {
	bytes := address.As16()
	if address.Is4() {
		ipv4 := address.As4()
		return int((ipv4[bitIndex/8] >> (7 - bitIndex%8)) & 1)
	}
	return int((bytes[bitIndex/8] >> (7 - bitIndex%8)) & 1)
}

func collapseCoveredPrefixes(node *prefixCoverageNode, remainingBits int) bool {
	if node == nil || node.covered {
		return node != nil && node.covered
	}
	if remainingBits == 0 {
		return false
	}
	leftCovered := collapseCoveredPrefixes(node.children[0], remainingBits-1)
	rightCovered := collapseCoveredPrefixes(node.children[1], remainingBits-1)
	if leftCovered && rightCovered {
		node.covered = true
		node.children = [2]*prefixCoverageNode{}
	}
	return node.covered
}

func isPositiveConditionOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "foranyvalue:")
	return operator == "stringequals" || operator == "arnequals" || operator == "stringlike" || operator == "arnlike"
}

func isPositiveIfExistsOperator(operator string) bool {
	operator = strings.ToLower(operator)
	if !strings.HasSuffix(operator, "ifexists") {
		return false
	}
	operator = strings.TrimPrefix(operator, "foranyvalue:")
	operator = strings.TrimPrefix(operator, "forallvalues:")
	operator = strings.TrimSuffix(operator, "ifexists")
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

func denyConditionHasTransportBypass(condition map[string]map[string]json.RawMessage) bool {
	for operator, entries := range condition {
		for key, rawValue := range entries {
			switch {
			case strings.EqualFold(operator, "Bool") && strings.EqualFold(key, "aws:SecureTransport"):
				values, err := decodeStringList(rawValue)
				if err == nil && len(values) == 1 && strings.EqualFold(values[0], "false") {
					return true
				}
			case strings.EqualFold(operator, "NumericLessThan") && strings.EqualFold(key, "s3:TlsVersion"):
				if tlsMinimumVersionDenyHasBypass(rawValue) {
					return true
				}
			}
		}
	}
	return false
}

func tlsMinimumVersionDenyHasBypass(rawValues json.RawMessage) bool {
	values, err := decodeNumericList(rawValues)
	if err != nil || len(values) == 0 {
		return false
	}
	for _, minimumVersion := range values {
		if minimumVersion > knownPublicS3TLSVersion {
			return false
		}
	}
	return true
}

func decodeNumericList(data []byte) ([]float64, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	values, ok := decoded.([]any)
	if !ok {
		values = []any{decoded}
	}

	result := make([]float64, 0, len(values))
	for _, value := range values {
		var rawValue string
		switch typedValue := value.(type) {
		case json.Number:
			rawValue = typedValue.String()
		case string:
			rawValue = typedValue
		default:
			return nil, fmt.Errorf("expected a number or list of numbers")
		}
		parsedValue, err := strconv.ParseFloat(rawValue, 64)
		if err != nil || math.IsNaN(parsedValue) || math.IsInf(parsedValue, 0) {
			return nil, fmt.Errorf("invalid numeric condition value %q", rawValue)
		}
		result = append(result, parsedValue)
	}
	return result, nil
}

type denyConditionResult uint8

const (
	denyDoesNotBlockPublic denyConditionResult = iota
	denyBlocksPublic
	denyUnknown
)

func classifyDenyCondition(
	condition map[string]map[string]json.RawMessage,
	principalKind policyPrincipalKind,
) denyConditionResult {
	if len(condition) == 0 {
		return denyBlocksPublic
	}
	if denyConditionHasTransportBypass(condition) {
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
			normalizedKey := strings.ToLower(key)
			if _, ok := trustedConditionKeys[normalizedKey]; !ok {
				return denyUnknown
			}
			if principalKind == policyPrincipalAnonymous && normalizedKey == "aws:principalaccount" {
				switch classifyKnownConditionValue(operator, rawValues, "anonymous") {
				case conditionPublic:
					return denyBlocksPublic
				case conditionRestricted:
					return denyDoesNotBlockPublic
				default:
					return denyUnknown
				}
			}
			if strings.EqualFold(operator, "Null") {
				values, err := decodeStringList(rawValues)
				if err != nil || len(values) != 1 {
					return denyUnknown
				}
				keyPresent, presenceKnown := policyConditionKeyPresence(principalKind, normalizedKey)
				if presenceKnown {
					switch {
					case strings.EqualFold(values[0], "true"):
						if keyPresent {
							return denyDoesNotBlockPublic
						}
						return denyBlocksPublic
					case strings.EqualFold(values[0], "false"):
						if keyPresent {
							return denyBlocksPublic
						}
						return denyDoesNotBlockPublic
					default:
						return denyUnknown
					}
				}
				if principalKind == policyPrincipalAuthenticated {
					return denyUnknown
				}
				switch {
				case strings.EqualFold(values[0], "true"):
					return denyBlocksPublic
				case strings.EqualFold(values[0], "false"):
					return denyDoesNotBlockPublic
				default:
					return denyUnknown
				}
			}
			if principalKind == policyPrincipalAuthenticated {
				return denyUnknown
			}
			fixed, err := conditionValuesAreFixed(rawValues)
			if err != nil || !fixed {
				return denyUnknown
			}
			if isPositiveIfExistsOperator(operator) {
				return denyBlocksPublic
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

func policyConditionKeyPresence(principalKind policyPrincipalKind, key string) (bool, bool) {
	switch key {
	case "aws:principalaccount":
		return true, true
	case "aws:principalarn":
		return principalKind == policyPrincipalAuthenticated, true
	default:
		return false, false
	}
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

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	iam "github.com/Method-Security/methodaws/generated/go/iam"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamaws "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateIamRoles retrieves all IAM roles with their attached policies
func enumerateIamRoles(ctx context.Context, cfg aws.Config, excludeAWSManagedRoles bool) ([]*iam.IamRoles, []string) {
	log := svc1log.FromContext(ctx)
	client := iamaws.NewFromConfig(cfg)
	var iamRoles []*iam.IamRoles
	var errors []string

	// Get all roles
	roles, errs := getAllRoles(ctx, client)
	errors = append(errors, errs...)

	log.Info("Processing IAM roles", svc1log.SafeParam("roleCount", len(roles)))

	// Filter out default roles if requested
	if excludeAWSManagedRoles {
		filteredRoles := make([]types.Role, 0, len(roles))
		for _, role := range roles {
			if !isAWSManagedRole(role) {
				filteredRoles = append(filteredRoles, role)
			}
		}
		roles = filteredRoles
		log.Info("Filtered default roles",
			svc1log.SafeParam("remainingRoleCount", len(roles)))
	}

	for _, role := range roles {
		iamRole, errs := processRole(ctx, client, role)
		if iamRole != nil {
			iamRoles = append(iamRoles, iamRole)
		}
		errors = append(errors, errs...)
	}

	return iamRoles, errors
}

// getAllRoles retrieves all IAM roles
func getAllRoles(ctx context.Context, client *iamaws.Client) ([]types.Role, []string) {
	var roles []types.Role
	var errors []string

	paginator := iamaws.NewListRolesPaginator(client, &iamaws.ListRolesInput{})
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to list roles: %s", err.Error()))
			break
		}
		roles = append(roles, result.Roles...)
	}

	return roles, errors
}

// processRole converts a role and enriches it with policy information
func processRole(ctx context.Context, client *iamaws.Client, role types.Role) (*iam.IamRoles, []string) {
	if aws.ToString(role.Arn) == "" || aws.ToString(role.RoleName) == "" {
		return nil, []string{fmt.Sprintf("role missing required ARN or name (arn=%q, name=%q)",
			aws.ToString(role.Arn), aws.ToString(role.RoleName))}
	}
	var errors []string

	// Get attached policies
	attachedPolicies, errs := getAttachedPoliciesForRole(ctx, client, role)
	errors = append(errors, errs...)

	// Convert role last used if present
	var roleLastUsed *iam.RoleLastUsed
	if role.RoleLastUsed != nil {
		roleLastUsed = &iam.RoleLastUsed{
			LastUsedDate: role.RoleLastUsed.LastUsedDate,
			Region:       role.RoleLastUsed.Region,
		}
	}

	// Create IAM role with nested structure
	iamRole := &iam.IamRoles{
		Identification: &iam.IamRoleIdentificationInfo{
			Arn:      *role.Arn,
			RoleName: *role.RoleName,
		},
		Configuration: &iam.IamRoleConfigurationInfo{
			CreateDate:   role.CreateDate,
			RoleLastUsed: roleLastUsed,
		},
		Resources: &iam.IamRoleResourceInfo{
			AttachedPolicies: attachedPolicies,
		},
	}

	return iamRole, errors
}

// getAttachedPoliciesForRole gets all attached policies for a role with their documents
func getAttachedPoliciesForRole(ctx context.Context, client *iamaws.Client, role types.Role) ([]*iam.AttachedPolicy, []string) {
	var attachedPolicies []*iam.AttachedPolicy
	var errors []string

	// List attached policies
	paginator := iamaws.NewListAttachedRolePoliciesPaginator(client, &iamaws.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	})

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to list attached policies for role %s: %v", *role.RoleName, err))
			break
		}

		for _, policy := range result.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) != "" && aws.ToString(policy.PolicyName) != "" {
				policyDoc, err := getPolicyDocument(ctx, client, *policy.PolicyArn)
				if err != nil {
					errors = append(errors, fmt.Sprintf("failed to get policy document for %s attached to role %s: %v",
						*policy.PolicyArn, *role.RoleName, err))
				}

				attachedPolicy := &iam.AttachedPolicy{
					Identification: &iam.AttachedPolicyIdentificationInfo{
						Arn:        *policy.PolicyArn,
						PolicyName: *policy.PolicyName,
					},
					Configuration: &iam.AttachedPolicyConfigurationInfo{
						PolicyDocument: policyDoc,
					},
				}

				attachedPolicies = append(attachedPolicies, attachedPolicy)
			} else {
				errors = append(errors, fmt.Sprintf("attached policy for role %s missing required ARN or name (arn=%q, name=%q)",
					*role.RoleName, aws.ToString(policy.PolicyArn), aws.ToString(policy.PolicyName)))
			}
		}
	}

	return attachedPolicies, errors
}

// getPolicyDocument retrieves the policy document for a given policy ARN
func getPolicyDocument(ctx context.Context, client *iamaws.Client, policyArn string) (*string, error) {
	// Get policy to find default version
	policy, err := client.GetPolicy(ctx, &iamaws.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy %s: %w", policyArn, err)
	}

	if policy == nil || policy.Policy == nil || aws.ToString(policy.Policy.DefaultVersionId) == "" {
		return nil, fmt.Errorf("policy %s missing default version", policyArn)
	}

	// Get the policy version document
	version, err := client.GetPolicyVersion(ctx, &iamaws.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy version for %s: %w", policyArn, err)
	}

	if version == nil || version.PolicyVersion == nil || aws.ToString(version.PolicyVersion.Document) == "" {
		return nil, fmt.Errorf("policy %s version %s missing document", policyArn, *policy.Policy.DefaultVersionId)
	}

	// IAM uses RFC 3986 encoding; preserve plain JSON and literal '+' characters.
	decodedDoc := *version.PolicyVersion.Document
	if !json.Valid([]byte(decodedDoc)) {
		decodedDoc, err = url.PathUnescape(decodedDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to decode policy %s document: %w", policyArn, err)
		}
	}

	var formatted bytes.Buffer
	if err := json.Indent(&formatted, []byte(decodedDoc), "", "  "); err != nil {
		return nil, fmt.Errorf("invalid JSON document for policy %s: %w", policyArn, err)
	}

	return aws.String(formatted.String()), nil
}

var serviceLinkedRoleArnRe = regexp.MustCompile(
	`^arn:aws[a-z-]*:iam::\d{12}:role/aws-service-role/`,
)

// isServiceLinkedRole returns true if the role is an AWS service-linked role.
func isServiceLinkedRole(role types.Role) bool {
	if role.Path != nil && strings.HasPrefix(*role.Path, "/aws-service-role/") {
		return true
	}

	// Fallback if Path is missing
	if role.Arn != nil && serviceLinkedRoleArnRe.MatchString(*role.Arn) {
		return true
	}

	return false
}

// isIdentityCenterRole returns true if the role was created by IAM Identity Center (SSO).
func isIdentityCenterRole(role types.Role) bool {
	// Identity Center roles always start with AWSReservedSSO_
	if role.RoleName != nil && strings.HasPrefix(*role.RoleName, "AWSReservedSSO_") {
		return true
	}

	// Extra safety: path used by SSO-managed roles
	if role.Path != nil && strings.Contains(*role.Path, "/aws-reserved/sso.amazonaws.com/") {
		return true
	}

	return false
}

// isControlTowerRole returns true if the role is created/required by AWS Control Tower.
func isControlTowerRole(role types.Role) bool {
	return role.RoleName != nil && *role.RoleName == "AWSControlTowerExecution"
}

// isAWSManagedRole returns true if the role is AWS-shipped (created and managed by AWS).
//
// This includes:
//   - Service-linked roles
//   - IAM Identity Center (SSO) roles
//   - Control Tower roles
func isAWSManagedRole(role types.Role) bool {
	return isServiceLinkedRole(role) ||
		isIdentityCenterRole(role) ||
		isControlTowerRole(role)
}

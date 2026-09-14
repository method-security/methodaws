package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
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
		if role.Arn == nil {
			log.Warn("role ARN is nil for role", svc1log.SafeParam("role", role))
			errors = append(errors, fmt.Sprintf("role ARN is nil for role %s", aws.ToString(role.RoleName)))
			continue
		}
		if role.RoleName == nil {
			log.Warn("role name is nil for role", svc1log.SafeParam("role", role))
			errors = append(errors, fmt.Sprintf("role name is nil for role %s", *role.Arn))
			continue
		}
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
			// Discover resource references from policy documents
			LambdaFunctions: discoverLambdaReferencesFromPolicies(attachedPolicies),
			Ec2Instances:    discoverEc2ReferencesFromPolicies(attachedPolicies),
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
			if policy.PolicyArn != nil && policy.PolicyName != nil {
				policyDoc, err := getPolicyDocument(ctx, client, *policy.PolicyArn)
				if err != nil {
					errors = append(errors, fmt.Sprintf("failed to get policy document for %s: %v", *policy.PolicyArn, err))
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

	if policy.Policy.DefaultVersionId == nil {
		return nil, nil
	}

	// Get the policy version document
	version, err := client.GetPolicyVersion(ctx, &iamaws.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy version for %s: %w", policyArn, err)
	}

	if version.PolicyVersion.Document == nil {
		return nil, nil
	}

	// Decode and format the policy document
	decodedDoc, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return version.PolicyVersion.Document, nil // Return original if decode fails
	}

	// Pretty format JSON if possible
	var jsonDoc interface{}
	if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
		if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
			prettyJSONStr := string(prettyJSON)
			return &prettyJSONStr, nil
		}
	}

	return &decodedDoc, nil
}

// Resource discovery functions with deduplication
func discoverLambdaReferencesFromPolicies(policies []*iam.AttachedPolicy) []*common.LambdaReference {
	lambdaMap := make(map[string]*common.LambdaReference)

	// Regex to match Lambda function ARNs in policy documents
	lambdaArnRegex := regexp.MustCompile(`arn:aws[a-z-]*:lambda:([^:]+):([^:]+):function:([^"'\s]+)`)

	for _, policy := range policies {
		if policy.Configuration != nil && policy.Configuration.PolicyDocument != nil {
			matches := lambdaArnRegex.FindAllStringSubmatch(*policy.Configuration.PolicyDocument, -1)
			for _, match := range matches {
				if len(match) > 3 {
					arn := match[0]
					region := match[1]
					functionName := match[3]

					key := arn
					if _, exists := lambdaMap[key]; !exists {
						lambdaMap[key] = &common.LambdaReference{
							Arn:          arn,
							FunctionName: &functionName,
							Region:       region,
						}
					}
				}
			}
		}
	}

	var lambdaFunctions []*common.LambdaReference
	for _, lambda := range lambdaMap {
		lambdaFunctions = append(lambdaFunctions, lambda)
	}
	return lambdaFunctions
}

func discoverEc2ReferencesFromPolicies(policies []*iam.AttachedPolicy) []*common.Ec2InstanceReference {
	ec2Map := make(map[string]*common.Ec2InstanceReference)

	// Regex to match EC2 instance ARNs and instance IDs in policy documents
	ec2ArnRegex := regexp.MustCompile(`arn:aws[a-z-]*:ec2:([^:]+):([^:]+):instance/([^"'\s]+)`)
	ec2IdRegex := regexp.MustCompile(`"(i-[a-f0-9]{8,17})"`) // Instance ID pattern

	for _, policy := range policies {
		if policy.Configuration != nil && policy.Configuration.PolicyDocument != nil {
			// Look for ARNs first
			matches := ec2ArnRegex.FindAllStringSubmatch(*policy.Configuration.PolicyDocument, -1)
			for _, match := range matches {
				if len(match) > 3 {
					region := match[1]
					instanceID := match[3]

					key := instanceID
					if _, exists := ec2Map[key]; !exists {
						ec2Map[key] = &common.Ec2InstanceReference{
							Id:     instanceID,
							Region: region,
						}
					}
				}
			}

			// Also look for standalone instance IDs
			instanceMatches := ec2IdRegex.FindAllStringSubmatch(*policy.Configuration.PolicyDocument, -1)
			for _, match := range instanceMatches {
				if len(match) > 1 {
					instanceID := match[1]
					key := instanceID
					if _, exists := ec2Map[key]; !exists {
						// We don't have region info from standalone ID, use empty region
						ec2Map[key] = &common.Ec2InstanceReference{
							Id:     instanceID,
							Region: "", // Region unknown from policy alone
						}
					}
				}
			}
		}
	}

	var ec2Instances []*common.Ec2InstanceReference
	for _, instance := range ec2Map {
		ec2Instances = append(ec2Instances, instance)
	}
	return ec2Instances
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

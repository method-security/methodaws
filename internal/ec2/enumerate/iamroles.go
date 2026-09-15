package enumerate

import (
	"context"
	"fmt"
	"strings"

	"github.com/Method-Security/methodaws/generated/go/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iamaws "github.com/aws/aws-sdk-go-v2/service/iam"
)

type instanceProfileResult struct {
	output *iamaws.GetInstanceProfileOutput
	err    error
}

// Cache profile responses, including failures, by full ARN for this enumeration run.
type instanceProfileCache map[string]instanceProfileResult

func (cache instanceProfileCache) resolveRole(ctx context.Context, client *iamaws.Client, attached *types.IamInstanceProfile) (*common.IamRoleReference, error) {
	if attached == nil {
		return nil, nil
	}
	profileARN := aws.ToString(attached.Arn)
	parsed, err := arn.Parse(profileARN)
	if err != nil || parsed.Service != "iam" || parsed.AccountID == "" || parsed.Region != "" ||
		!strings.HasPrefix(parsed.Resource, "instance-profile/") || strings.HasSuffix(parsed.Resource, "/") {
		return nil, fmt.Errorf("missing or invalid instance profile ARN %q", profileARN)
	}

	result, ok := cache[profileARN]
	if !ok {
		profileName := parsed.Resource[strings.LastIndex(parsed.Resource, "/")+1:]
		result.output, result.err = client.GetInstanceProfile(ctx, &iamaws.GetInstanceProfileInput{
			InstanceProfileName: aws.String(profileName),
		})
		cache[profileARN] = result
	}
	if result.err != nil {
		return nil, fmt.Errorf("failed to resolve instance profile %s: %w", profileARN, result.err)
	}
	if result.output == nil || result.output.InstanceProfile == nil {
		return nil, fmt.Errorf("instance profile %s lookup returned no profile", profileARN)
	}
	profile := result.output.InstanceProfile
	if aws.ToString(profile.Arn) != profileARN ||
		(aws.ToString(attached.Id) != "" && aws.ToString(profile.InstanceProfileId) != *attached.Id) {
		return nil, fmt.Errorf("instance profile %s lookup returned a different or missing profile identity", profileARN)
	}
	if len(profile.Roles) == 0 {
		return nil, nil
	}
	if len(profile.Roles) != 1 {
		return nil, fmt.Errorf("instance profile %s returned multiple roles", profileARN)
	}

	role := profile.Roles[0]
	roleARN := aws.ToString(role.Arn)
	parsedRole, err := arn.Parse(roleARN)
	if err != nil || parsedRole.Service != "iam" || parsedRole.Region != "" ||
		parsedRole.Partition != parsed.Partition || parsedRole.AccountID != parsed.AccountID ||
		!strings.HasPrefix(parsedRole.Resource, "role/") || strings.HasSuffix(parsedRole.Resource, "/") {
		return nil, fmt.Errorf("instance profile %s returned a missing or invalid role ARN %q", profileARN, roleARN)
	}
	var roleName *string
	if aws.ToString(role.RoleName) != "" {
		roleName = role.RoleName
	}
	return &common.IamRoleReference{
		Arn:      roleARN,
		RoleName: roleName,
	}, nil
}

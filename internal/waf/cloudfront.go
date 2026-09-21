package waf

import (
	"context"
	"fmt"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

type cloudFrontAPI interface {
	ListDistributionsByWebACLId(context.Context, *cloudfront.ListDistributionsByWebACLIdInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsByWebACLIdOutput, error)
}

func distributionsForWebACL(ctx context.Context, client cloudFrontAPI, webACLARN string) ([]*common.CloudFrontDistributionReference, []string) {
	parent, err := arn.Parse(webACLARN)
	if err != nil {
		return nil, []string{fmt.Sprintf("Invalid WebACL ARN %q: %v", webACLARN, err)}
	}
	var distributions []*common.CloudFrontDistributionReference
	var errors []string
	var marker *string
	for {
		output, err := client.ListDistributionsByWebACLId(ctx, &cloudfront.ListDistributionsByWebACLIdInput{
			WebACLId: aws.String(webACLARN), Marker: marker,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("ListDistributionsByWebACLId %s: %v", webACLARN, err))
			break
		}
		if output == nil || output.DistributionList == nil {
			errors = append(errors, fmt.Sprintf("ListDistributionsByWebACLId %s returned no distribution list", webACLARN))
			break
		}
		for _, distribution := range output.DistributionList.Items {
			parsed, err := arn.Parse(aws.ToString(distribution.ARN))
			parts := strings.Split(parsed.Resource, "/")
			if err != nil || parsed.Service != "cloudfront" || parsed.Partition != parent.Partition ||
				parsed.AccountID != parent.AccountID || parsed.Region != "" || len(parts) != 2 ||
				parts[0] != "distribution" || !hasValue(distribution.Id) || parts[1] != *distribution.Id {
				errors = append(errors, fmt.Sprintf("WebACL %s: invalid associated distribution ARN %q", webACLARN, aws.ToString(distribution.ARN)))
				continue
			}
			if hasValue(distribution.WebACLId) && *distribution.WebACLId != webACLARN {
				errors = append(errors, fmt.Sprintf("WebACL %s: distribution %s reports a different WebACL", webACLARN, parsed.String()))
				continue
			}
			distributions = append(distributions, &common.CloudFrontDistributionReference{
				Arn: parsed.String(), DomainName: distribution.DomainName,
			})
		}
		if !aws.ToBool(output.DistributionList.IsTruncated) {
			break
		}
		nextMarker := output.DistributionList.NextMarker
		if !hasValue(nextMarker) || aws.ToString(marker) == *nextMarker {
			errors = append(errors, fmt.Sprintf("ListDistributionsByWebACLId %s returned a missing or repeated pagination marker", webACLARN))
			break
		}
		marker = nextMarker
	}
	return distributions, errors
}

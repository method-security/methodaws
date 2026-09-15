package enumerate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	common "github.com/Method-Security/methodaws/generated/go/common"
	"github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// Only recognized AWS endpoint forms can produce backend identities. Custom DNS
// names remain unlinked; substrings such as "ec2-" are not evidence of ownership.
const originRegionPattern = `[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+`

var (
	s3OriginDomain         = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3(?:(?:-website[.-]|[.-])(` + originRegionPattern + `))?\.([a-z0-9.-]+)$`)
	elbOriginDomain        = regexp.MustCompile(`^[a-z0-9-]+\.(` + originRegionPattern + `)\.elb\.([a-z0-9.-]+)$`)
	nlbOriginDomain        = regexp.MustCompile(`^[a-z0-9-]+\.elb\.(` + originRegionPattern + `)\.([a-z0-9.-]+)$`)
	ec2OriginDomain        = regexp.MustCompile(`^ec2-[0-9]+-[0-9]+-[0-9]+-[0-9]+\.(` + originRegionPattern + `)\.compute\.([a-z0-9.-]+)$`)
	ec2LegacyOriginDomain  = regexp.MustCompile(`^ec2-[0-9]+-[0-9]+-[0-9]+-[0-9]+\.compute-1\.amazonaws\.com$`)
	apiGatewayOriginDomain = regexp.MustCompile(`^([a-z0-9]+)\.execute-api\.(` + originRegionPattern + `)\.([a-z0-9.-]+)$`)
)

// Regional patterns capture region and DNS suffix last. Regionless S3 uses the
// commercial global endpoint; regional endpoints must match their partition.
func matchOriginDomain(pattern *regexp.Regexp, domainName string) []string {
	matches := pattern.FindStringSubmatch(domainName)
	if len(matches) < 3 {
		return nil
	}
	region := matches[len(matches)-2]
	if region == "" {
		region = "us-east-1"
	}
	suffix, err := utils.AWSDNSSuffixForRegion(region)
	if err != nil || matches[len(matches)-1] != suffix {
		return nil
	}
	return matches
}

func resolveOriginBackend(ctx context.Context, awsConfig aws.Config, domainName string, originType cloudfrontfern.CloudFrontResourceType, accountID string) (*cloudfrontfern.CloudFrontOriginBackend, error) {
	switch originType {
	case cloudfrontfern.CloudFrontResourceTypeS3:
		matches := matchOriginDomain(s3OriginDomain, domainName)
		if len(matches) < 2 {
			return nil, fmt.Errorf("invalid S3 origin domain: %s", domainName)
		}
		return &cloudfrontfern.CloudFrontOriginBackend{
			Type: "s3", S3: &cloudfrontfern.S3OriginBackend{BucketName: matches[1]},
		}, nil
	case cloudfrontfern.CloudFrontResourceTypeLoadBalancer:
		lb, err := resolveLoadBalancer(ctx, awsConfig, domainName)
		if err != nil {
			return nil, err
		}
		return &cloudfrontfern.CloudFrontOriginBackend{Type: "load_balancer", LoadBalancer: lb}, nil
	case cloudfrontfern.CloudFrontResourceTypeEc2:
		instanceARN, err := resolveEC2InstanceARN(ctx, awsConfig, domainName, accountID)
		if err != nil {
			return nil, err
		}
		return &cloudfrontfern.CloudFrontOriginBackend{
			Type: "ec2", Ec2: &cloudfrontfern.Ec2OriginBackend{Arn: instanceARN},
		}, nil
	case cloudfrontfern.CloudFrontResourceTypeApiGateway:
		matches := matchOriginDomain(apiGatewayOriginDomain, domainName)
		if len(matches) < 3 {
			return nil, fmt.Errorf("invalid API Gateway origin domain: %s", domainName)
		}
		// The hostname identifies the API and region, but not its owning account.
		return &cloudfrontfern.CloudFrontOriginBackend{
			Type: "api_gateway", ApiGateway: &cloudfrontfern.ApiGatewayOriginBackend{Id: matches[1], Region: matches[2]},
		}, nil
	default:
		return nil, nil
	}
}

func resolveLoadBalancer(ctx context.Context, awsConfig aws.Config, domainName string) (*common.LoadBalancerReference, error) {
	matches := matchOriginDomain(elbOriginDomain, domainName)
	if len(matches) < 2 {
		matches = matchOriginDomain(nlbOriginDomain, domainName)
	}
	if len(matches) < 2 {
		return nil, fmt.Errorf("invalid load balancer origin domain: %s", domainName)
	}
	awsConfig.Region = matches[1]
	client := elasticloadbalancingv2.NewFromConfig(awsConfig)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lb := range page.LoadBalancers {
			if aws.ToString(lb.DNSName) != domainName {
				continue
			}
			parsed, err := arn.Parse(aws.ToString(lb.LoadBalancerArn))
			if err != nil || parsed.Partition == "" || parsed.Service != "elasticloadbalancing" ||
				parsed.Region == "" || parsed.AccountID == "" || !strings.HasPrefix(parsed.Resource, "loadbalancer/") {
				return nil, fmt.Errorf("load balancer for %s has an incomplete ARN", domainName)
			}
			var lbType common.LoadBalancerType
			switch lb.Type {
			case elbtypes.LoadBalancerTypeEnumApplication:
				lbType = common.LoadBalancerTypeApplication
			case elbtypes.LoadBalancerTypeEnumNetwork:
				lbType = common.LoadBalancerTypeNetwork
			default:
				return nil, fmt.Errorf("unsupported origin load balancer type %q for %s", lb.Type, domainName)
			}
			return &common.LoadBalancerReference{
				Arn: *lb.LoadBalancerArn, Region: parsed.Region, Type: lbType, DnsName: lb.DNSName,
			}, nil
		}
	}
	return nil, fmt.Errorf("ELBv2 not found for origin domain: %s", domainName)
}

func resolveEC2InstanceARN(ctx context.Context, awsConfig aws.Config, domainName, accountID string) (string, error) {
	matches := matchOriginDomain(ec2OriginDomain, domainName)
	if len(matches) >= 2 {
		awsConfig.Region = matches[1]
	} else if ec2LegacyOriginDomain.MatchString(domainName) {
		awsConfig.Region = "us-east-1"
	} else {
		return "", fmt.Errorf("invalid EC2 origin domain: %s", domainName)
	}
	client := ec2.NewFromConfig(awsConfig)
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if aws.ToString(instance.PublicDnsName) != domainName {
					continue
				}
				// DescribeInstances is scoped to the authenticated account. Prefer
				// the explicit owner when AWS supplies it.
				owner := accountID
				if aws.ToString(reservation.OwnerId) != "" {
					owner = *reservation.OwnerId
				}
				if aws.ToString(instance.InstanceId) == "" || owner == "" {
					return "", fmt.Errorf("EC2 instance for %s has an incomplete identity", domainName)
				}
				return utils.BuildRegionalARN(awsConfig.Region, "ec2", owner, "instance/"+*instance.InstanceId)
			}
		}
	}
	return "", fmt.Errorf("EC2 instance not found for origin domain: %s", domainName)
}

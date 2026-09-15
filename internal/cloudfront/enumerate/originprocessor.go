package enumerate

import (
	"context"
	"fmt"

	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	common "github.com/Method-Security/methodaws/generated/go/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func classifyOriginType(domainName string) cloudfrontfern.CloudFrontResourceType {
	switch {
	case matchOriginDomain(s3OriginDomain, domainName) != nil:
		return cloudfrontfern.CloudFrontResourceTypeS3
	case matchOriginDomain(elbOriginDomain, domainName) != nil, matchOriginDomain(nlbOriginDomain, domainName) != nil:
		return cloudfrontfern.CloudFrontResourceTypeLoadBalancer
	case matchOriginDomain(ec2OriginDomain, domainName) != nil, ec2LegacyOriginDomain.MatchString(domainName):
		return cloudfrontfern.CloudFrontResourceTypeEc2
	case matchOriginDomain(apiGatewayOriginDomain, domainName) != nil:
		return cloudfrontfern.CloudFrontResourceTypeApiGateway
	default:
		return cloudfrontfern.CloudFrontResourceTypeUnknown
	}
}

func processOrigins(ctx context.Context, awsConfig aws.Config, origins []types.Origin, accountID string) ([]*cloudfrontfern.CloudFrontDistributionOrigin, []string) {
	var fernOrigins []*cloudfrontfern.CloudFrontDistributionOrigin
	var errors []string
	for _, origin := range origins {
		if aws.ToString(origin.Id) == "" {
			errors = append(errors, "Origin ID is empty")
			continue
		}
		fernOrigin, err := processOrigin(ctx, awsConfig, origin, accountID)
		fernOrigins = append(fernOrigins, fernOrigin)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Origin %q: %v", *origin.Id, err))
		}
	}
	return fernOrigins, errors
}

func processOrigin(ctx context.Context, awsConfig aws.Config, origin types.Origin, accountID string) (*cloudfrontfern.CloudFrontDistributionOrigin, error) {
	resourceType := classifyOriginType(aws.ToString(origin.DomainName))
	if origin.VpcOriginConfig != nil {
		resourceType = cloudfrontfern.CloudFrontResourceTypeVpcOrigin
	}

	backend, err := resolveOriginBackend(ctx, awsConfig, aws.ToString(origin.DomainName), resourceType, accountID)
	if backend != nil && backend.LoadBalancer != nil {
		switch backend.LoadBalancer.Type {
		case common.LoadBalancerTypeApplication:
			resourceType = cloudfrontfern.CloudFrontResourceTypeApplicationLoadBalancer
		case common.LoadBalancerTypeNetwork:
			resourceType = cloudfrontfern.CloudFrontResourceTypeNetworkLoadBalancer
		}
	}

	var connectionTimeout, connectionAttempts *int
	if origin.ConnectionTimeout != nil {
		value := int(*origin.ConnectionTimeout)
		connectionTimeout = &value
	}
	if origin.ConnectionAttempts != nil {
		value := int(*origin.ConnectionAttempts)
		connectionAttempts = &value
	}
	var customHeaders []string
	if origin.CustomHeaders != nil {
		for _, header := range origin.CustomHeaders.Items {
			if header.HeaderName != nil {
				customHeaders = append(customHeaders, *header.HeaderName)
			}
		}
	}

	return &cloudfrontfern.CloudFrontDistributionOrigin{
		Identification: &cloudfrontfern.CloudFrontDistributionOriginIdentificationInfo{
			Id:         aws.ToString(origin.Id),
			DomainName: origin.DomainName,
		},
		Configuration: &cloudfrontfern.CloudFrontDistributionOriginConfigurationInfo{
			ResourceType:       resourceType,
			Path:               origin.OriginPath,
			CustomHeaders:      customHeaders,
			ConnectionAttempts: connectionAttempts,
			ConnectionTimeout:  connectionTimeout,
		},
		Backend: backend,
	}, err
}

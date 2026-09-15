package apigateway

import (
	"context"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	common "github.com/Method-Security/methodaws/generated/go/common"
	"github.com/aws/aws-sdk-go-v2/aws"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateAPIGateway enumerates API Gateways based on the provided configuration
func EnumerateAPIGateway(ctx context.Context, awsConfig aws.Config, config apigatewayfern.ApiGatewayEnumerateConfig) *apigatewayfern.ApiGatewayEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting API Gateway enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("versionsCount", len(config.Versions)))

	// Initialize report
	report := &apigatewayfern.ApiGatewayEnumerateReport{
		Result: &apigatewayfern.ApiGatewayEnumerateResult{},
		Config: &config,
	}

	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
	var allErrors []string

	// Process each version requested
	if config.Versions != nil {
		for _, version := range config.Versions {
			switch version {
			case apigatewayfern.ApiGatewayVersionV1:
				log.Info("Processing v1 API Gateways (REST APIs)")
				v1APIs, errors := enumerateV1ApiGatewaysAllRegions(ctx, awsConfig, config.Regions)
				allAPIGateways = append(allAPIGateways, v1APIs...)
				allErrors = append(allErrors, errors...)

			case apigatewayfern.ApiGatewayVersionV2:
				log.Info("Processing v2 API Gateways (HTTP APIs)")
				v2APIs, errors := enumerateV2ApiGatewaysAllRegions(ctx, awsConfig, config.Regions)
				allAPIGateways = append(allAPIGateways, v2APIs...)
				allErrors = append(allErrors, errors...)
			}
		}
	}

	// Marshal report
	if len(allAPIGateways) > 0 {
		report.Result.Apis = allAPIGateways
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed API Gateway enumeration",
		svc1log.SafeParam("totalApiGateways", len(allAPIGateways)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// convertInt32PtrToIntPtr converts *int32 to *int for compatibility
func convertInt32PtrToIntPtr(val *int32) *int {
	if val == nil {
		return nil
	}
	converted := int(*val)
	return &converted
}

// Helper functions for resource identification

func isIAMRole(arn string) bool {
	return strings.Contains(arn, ":iam:") && strings.Contains(arn, ":role/")
}

func isCloudWatchLogGroup(arn string) bool {
	return strings.Contains(arn, ":logs:") && strings.Contains(arn, ":log-group:")
}

// Helper function to identify resource type (removed - no longer used in simplified schema)

// createIamRoleReference creates an IAM role reference from an ARN
func createIamRoleReference(arn, region string) *common.IamRoleReference {
	if !isIAMRole(arn) {
		return nil
	}

	roleName := extractResourceNameFromArn(arn)
	if roleName == nil {
		return nil
	}

	return &common.IamRoleReference{
		Arn:      arn,
		RoleName: roleName,
		Region:   region,
	}
}

// createCloudWatchLogReference creates a CloudWatch log reference from an ARN
func createCloudWatchLogReference(arn, region string) *common.CloudWatchLogReference {
	if !isCloudWatchLogGroup(arn) {
		return nil
	}

	logGroupName := extractResourceNameFromArn(arn)
	if logGroupName == nil {
		return nil
	}

	return &common.CloudWatchLogReference{
		Arn:          arn,
		LogGroupName: *logGroupName,
		Region:       region,
	}
}

func extractResourceNameFromArn(arn string) *string {
	if arn == "" {
		return nil
	}

	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name != "" {
			return &name
		}
	}

	// Fallback: extract from colon-separated parts
	parts = strings.Split(arn, ":")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name != "" {
			return &name
		}
	}

	return nil
}

// analyzeAPISecurity performs security analysis on API Gateway configurations
func analyzeAPISecurity(routes []*apigatewayfern.Route, certificates []*apigatewayfern.Certificate, accessLogSettings *apigatewayfern.AccessLogSettings, corsConfig *apigatewayfern.CorsConfiguration, apiKeys []string) *apigatewayfern.ApiGatewaySecurity {
	if routes == nil {
		return nil
	}

	requiredAPIKeys := len(apiKeys) > 0
	hasCloudWatchLogging := accessLogSettings != nil
	hasCorsConfig := corsConfig != nil
	analysis := &apigatewayfern.ApiGatewaySecurity{
		HasCloudWatchLogging:  &hasCloudWatchLogging,
		AuthenticationMethods: []apigatewayfern.AuthorizationType{},
		TlsVersions:           []apigatewayfern.SecurityPolicy{},
		CorsConfigured:        &hasCorsConfig,
		ApiKeysRequired:       &requiredAPIKeys,
	}

	// Track unique authentication methods
	authMethods := make(map[apigatewayfern.AuthorizationType]bool)

	// Analyze routes for security posture
	for _, route := range routes {
		if route == nil {
			continue
		}

		// Track authentication methods
		if route.Configuration != nil && route.Configuration.Authorization != nil {
			authMethods[*route.Configuration.Authorization] = true
		}

		// Check for throttling
		if route.Configuration != nil && route.Configuration.Throttle != nil {
			hasThrottling := true
			analysis.HasThrottling = &hasThrottling
		}
	}

	// Convert auth methods map to slice
	for authType := range authMethods {
		analysis.AuthenticationMethods = append(analysis.AuthenticationMethods, authType)
	}

	// Extract TLS versions from certificates
	tlsVersions := make(map[apigatewayfern.SecurityPolicy]bool)
	for _, cert := range certificates {
		if cert != nil && cert.SecurityPolicy != nil {
			tlsVersions[*cert.SecurityPolicy] = true
		}
	}
	for tlsVersion := range tlsVersions {
		analysis.TlsVersions = append(analysis.TlsVersions, tlsVersion)
	}

	return analysis
}

// createRouteResources creates route-specific resource links from integration data (excluding integration itself)
func createRouteResources(integration *apigatewayfern.Integration, region string) *apigatewayfern.RouteResourceInfo {
	if integration == nil {
		return nil
	}

	links := &apigatewayfern.RouteResourceInfo{}

	// Extract resources based on integration type and backend
	switch integration.Type {
	case "aws_proxy":
		if awsProxy := integration.AwsProxy; awsProxy != nil && awsProxy.Backend != nil {
			// Set execution role if available
			links.ExecutionRole = createIamRoleReference(awsProxy.Backend.Arn, region)
		}

	case "vpc_link":
		// VPC Link details are stored in integration.backend only, no duplication in route resources
		// Only set VPC and security group references if needed for the route itself

	case "aws":
		if aws := integration.Aws; aws != nil && aws.Backend != nil {
			// Set execution role for AWS service integration
			links.ExecutionRole = createIamRoleReference(aws.Backend.Arn, region)
			if isCloudWatchLogGroup(aws.Backend.Arn) {
				links.CloudWatchLog = createCloudWatchLogReference(aws.Backend.Arn, region)
			}
		}
	}

	// Return nil if no resources were found
	if links.ExecutionRole == nil && links.CloudWatchLog == nil {
		return nil
	}

	return links
}

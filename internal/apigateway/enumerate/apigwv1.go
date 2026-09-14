package apigateway

import (
	"context"
	"fmt"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1ApiGatewaysAllRegions enumerates v1 API Gateways (REST APIs) across all specified regions
func enumerateV1ApiGatewaysAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v1 API Gateways in region", svc1log.SafeParam("region", region))
		apiGateways, errors := enumerateV1ApiGatewaysForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v1 API Gateways in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allAPIGateways = append(allAPIGateways, apiGateways...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v1 API Gateways in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("apiGatewayCount", len(apiGateways)))
	}

	return allAPIGateways, allErrors
}

// enumerateV1ApiGatewaysForRegion enumerates v1 API Gateways (REST APIs) for a specific region
func enumerateV1ApiGatewaysForRegion(ctx context.Context, cfg aws.Config, region string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	client := apigateway.NewFromConfig(regionCfg)
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	var apiGateways []*apigatewayfern.ApiGatewayInstance
	var errors []string

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve REST APIs page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("GetRestApis pagination failed in region %s: %s", region, err.Error()))
			break
		}
		if result == nil {
			errors = append(errors, fmt.Sprintf("GetRestApis returned no response in region %s", region))
			break
		}

		// Process APIs sequentially
		for _, api := range result.Items {
			if api.Id == nil {
				log.Warn("REST API ID is nil, skipping API", svc1log.SafeParam("region", region))
				errors = append(errors, "REST API ID is nil")
				continue
			}

			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				log.Warn("Failed to get stages for API",
					svc1log.SafeParam("region", region),
					svc1log.SafeParam("apiId", *api.Id),
					svc1log.Stacktrace(err))
				errors = append(errors, fmt.Sprintf("GetStages failed for API %s: %s", *api.Id, err.Error()))
				continue
			}
			if stages == nil {
				errors = append(errors, fmt.Sprintf("GetStages returned no response for API %s", *api.Id))
				continue
			}

			// Process each stage as a separate API Gateway instance
			for _, stage := range stages.Item {
				if stage.StageName == nil {
					log.Warn("Stage name is nil, skipping stage",
						svc1log.SafeParam("region", region),
						svc1log.SafeParam("apiId", *api.Id))
					errors = append(errors, fmt.Sprintf("Stage name is nil for API %s", *api.Id))
					continue
				}
				apiGw, errs := convertV1RestAPIToFern(ctx, client, api, stage, region)

				if apiGw != nil {
					apiGateways = append(apiGateways, apiGw)
				}
				// Add context to conversion errors
				for _, err := range errs {
					errors = append(errors, fmt.Sprintf("API %s stage %s: %s", *api.Id, *stage.StageName, err))
				}
			}
		}
	}

	return apiGateways, errors
}

// convertV1RestAPIToFern converts AWS REST API to Fern RestApiGateway struct
func convertV1RestAPIToFern(ctx context.Context, client *apigateway.Client, api types.RestApi, stage types.Stage, region string) (*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var errors []string

	// Construct base URL for this stage
	baseURL := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", *api.Id, region, *stage.StageName)

	// Get resources and methods with security info
	routes, errs := getRestAPIRoutes(ctx, client, *api.Id, region)
	errors = append(errors, errs...)

	// Get endpoint configuration (not used in simplified version)
	_, err := getEndpointConfiguration(api.EndpointConfiguration)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Endpoint configuration parsing failed for API %s: %s", *api.Id, err.Error()))
	}

	// Get certificates
	certificates, errs := getAPICertificates(ctx, client)
	for _, err := range errs {
		log.Warn("Certificate retrieval error",
			svc1log.SafeParam("apiId", *api.Id),
			svc1log.SafeParam("error", err))
		errors = append(errors, fmt.Sprintf("Certificate retrieval failed for API %s: %s", *api.Id, err))
	}

	// Get API keys and usage plans
	apiKeys, _, errs := getAPIKeysAndUsagePlans(ctx, client, *api.Id)
	for _, err := range errs {
		log.Warn("API keys/usage plans retrieval error",
			svc1log.SafeParam("apiId", *api.Id),
			svc1log.SafeParam("error", err))
		errors = append(errors, fmt.Sprintf("API keys/usage plans retrieval failed for API %s: %s", *api.Id, err))
	}

	// Get access log settings from stage
	accessLogSettings, err := getAccessLogSettings(stage)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Access log settings parsing failed for API %s stage %s: %s", *api.Id, *stage.StageName, err.Error()))
	}

	// Discover resource relationships
	// Resources are now nested within routes, no need for separate discovery

	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, nil, apiKeys)

	var stageName string
	if stage.StageName != nil {
		stageName = *stage.StageName
	}

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Id:     *api.Id,
		Name:   api.Name,
		Region: region,
		Url:    baseURL,
	}

	// Create configuration info
	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:             apigatewayfern.ApiGatewayVersionV1,
		Description:         api.Description,
		Stage:               &stageName,
		AccessLogSettings:   accessLogSettings,
		ClientCertificateId: stage.ClientCertificateId,
		Certificates:        certificates,
		Security:            securityAnalysis,
	}

	// Create resource info
	resources := &apigatewayfern.ApiGatewayResourceInfo{
		Routes: routes,
	}

	// Create ApiGatewayInstance
	apiGatewayInstance := &apigatewayfern.ApiGatewayInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return apiGatewayInstance, errors
}

// getRestAPIRoutes retrieves routes/paths for a REST API
func getRestAPIRoutes(ctx context.Context, client *apigateway.Client, apiID, region string) ([]*apigatewayfern.Route, []string) {
	log := svc1log.FromContext(ctx)
	var routes []*apigatewayfern.Route
	var errors []string

	// Paginate through all resources
	var allResources []types.Resource
	paginator := apigateway.NewGetResourcesPaginator(client, &apigateway.GetResourcesInput{RestApiId: &apiID})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to get resources for API",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("apiId", apiID),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("GetResources failed for API %s: %s", apiID, err.Error()))
			break
		}
		allResources = append(allResources, page.Items...)
	}

	for _, resource := range allResources {
		if resource.Id == nil || resource.Path == nil {
			errors = append(errors, fmt.Sprintf("Resource ID or path is missing for API %s", apiID))
			continue
		}
		for methodName := range resource.ResourceMethods {
			method, err := client.GetMethod(ctx, &apigateway.GetMethodInput{
				RestApiId:  &apiID,
				ResourceId: resource.Id,
				HttpMethod: &methodName,
			})
			if err != nil {
				resourcePath := "unknown"
				if resource.Path != nil {
					resourcePath = *resource.Path
				}
				log.Warn("Failed to get method for resource",
					svc1log.SafeParam("region", region),
					svc1log.SafeParam("apiId", apiID),
					svc1log.SafeParam("resourcePath", resourcePath),
					svc1log.SafeParam("resourceId", *resource.Id),
					svc1log.SafeParam("method", methodName),
					svc1log.Stacktrace(err))
				errors = append(errors, fmt.Sprintf("GetMethod failed for API %s, resource %s (%s), method %s: %s",
					apiID, resourcePath, *resource.Id, methodName, err.Error()))
				continue
			}
			if method == nil {
				errors = append(errors, fmt.Sprintf("GetMethod returned no response for API %s, resource %s", apiID, *resource.Id))
				continue
			}

			// Convert integration if present
			var integration *apigatewayfern.Integration
			if method.MethodIntegration != nil {
				integ, err := convertV1Integration(method.MethodIntegration, region)
				if err != nil {
					resourcePath := "unknown"
					if resource.Path != nil {
						resourcePath = *resource.Path
					}
					log.Warn("Failed to convert integration",
						svc1log.SafeParam("region", region),
						svc1log.SafeParam("apiId", apiID),
						svc1log.SafeParam("resourcePath", resourcePath),
						svc1log.SafeParam("method", methodName),
						svc1log.Stacktrace(err))
					errors = append(errors, fmt.Sprintf("Integration conversion failed for API %s, resource %s, method %s: %s",
						apiID, resourcePath, methodName, err.Error()))
				} else {
					integration = integ
				}
			}

			// Convert authorization type
			var authType *apigatewayfern.AuthorizationType
			if method.AuthorizationType != nil && *method.AuthorizationType != "" {
				switch *method.AuthorizationType {
				case "NONE":
					authTypeValue := apigatewayfern.AuthorizationTypeNone
					authType = &authTypeValue
				case "AWS_IAM":
					authTypeValue := apigatewayfern.AuthorizationTypeAwsIam
					authType = &authTypeValue
				case "CUSTOM":
					authTypeValue := apigatewayfern.AuthorizationTypeCustom
					authType = &authTypeValue
				case "COGNITO_USER_POOLS":
					authTypeValue := apigatewayfern.AuthorizationTypeCognitoUserPools
					authType = &authTypeValue
				}
			}

			// Get authorizer info if present (simplified - not included in route)
			_ = method.AuthorizerId

			// Create route-specific resource links
			resourceLinks := createRouteResources(integration, region)

			// Create resources only if there's something to include
			var resources *apigatewayfern.RouteResourceInfo
			if integration != nil || (resourceLinks != nil && (resourceLinks.ExecutionRole != nil || resourceLinks.CloudWatchLog != nil)) {
				resources = &apigatewayfern.RouteResourceInfo{}

				// Add integration if it exists
				if integration != nil {
					resources.Integration = integration
				}

				// Add other resource links if they exist
				if resourceLinks != nil {
					resources.ExecutionRole = resourceLinks.ExecutionRole
					resources.CloudWatchLog = resourceLinks.CloudWatchLog
				}
			}

			route := &apigatewayfern.Route{
				Identification: &apigatewayfern.RouteIdentificationInfo{
					Path:   *resource.Path,
					Method: methodName,
				},
				Configuration: &apigatewayfern.RouteConfigurationInfo{
					Authorization:  authType,
					ApiKeyRequired: method.ApiKeyRequired,
				},
			}
			// Add resources if they exist
			if resources != nil && (resources.Integration != nil || resources.ExecutionRole != nil || resources.CloudWatchLog != nil) {
				route.Resources = resources
			}
			routes = append(routes, route)
		}
	}

	return routes, errors
}

// convertV1Integration converts AWS API Gateway integration to Fern Integration with backend structure
// Returns detailed error messages for debugging integration conversion failures
func convertV1Integration(methodIntegration *types.Integration, region string) (*apigatewayfern.Integration, error) {
	switch methodIntegration.Type {
	case types.IntegrationTypeHttp:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP integration missing URI")
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        *methodIntegration.Uri,
			IsExternal: !strings.Contains(*methodIntegration.Uri, ".amazonaws.com"),
		}

		return &apigatewayfern.Integration{Type: "http", Http: &apigatewayfern.HttpIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeAws:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS integration missing ARN")
		}

		backend := &apigatewayfern.AwsServiceBackend{
			Arn:     *methodIntegration.Uri,
			Service: extractServiceFromArn(*methodIntegration.Uri),
			Region:  region,
		}

		return &apigatewayfern.Integration{Type: "aws", Aws: &apigatewayfern.AwsIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeHttpProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP Proxy integration missing URI")
		}

		// Check if this is a VPC Link integration (private load balancer)
		if isVpcLinkIntegration(methodIntegration) {
			backend := createLoadBalancerBackend(methodIntegration, region)
			return &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}}, nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        *methodIntegration.Uri,
			IsExternal: !strings.Contains(*methodIntegration.Uri, ".amazonaws.com"),
		}

		return &apigatewayfern.Integration{Type: "http_proxy", HttpProxy: &apigatewayfern.HttpProxyIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeAwsProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS Proxy integration missing ARN")
		}

		backend := &apigatewayfern.LambdaBackend{
			Arn:          *methodIntegration.Uri,
			FunctionName: extractResourceNameFromArn(*methodIntegration.Uri),
			Region:       region,
		}

		return &apigatewayfern.Integration{Type: "aws_proxy", AwsProxy: &apigatewayfern.AwsProxyIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeMock:
		backend := &apigatewayfern.MockBackend{}
		return &apigatewayfern.Integration{Type: "mock", Mock: &apigatewayfern.MockIntegration{
			Backend: backend,
		}}, nil

	default:
		return nil, fmt.Errorf("unsupported integration type: %s", methodIntegration.Type)
	}
}

// extractServiceFromArn extracts the service name from an AWS ARN
func extractServiceFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2] // Service is the 3rd element (0-indexed position 2)
	}
	return "unknown"
}

// isVpcLinkIntegration checks if the integration uses a VPC Link
func isVpcLinkIntegration(integration *types.Integration) bool {
	// In V1 API Gateway, VPC Link is indicated by connection type and connection ID
	return integration.ConnectionType == types.ConnectionTypeVpcLink &&
		integration.ConnectionId != nil
}

// createLoadBalancerBackend creates a LoadBalancerBackend from integration details
func createLoadBalancerBackend(integration *types.Integration, region string) *apigatewayfern.LoadBalancerBackend {
	if integration.Uri == nil || integration.ConnectionId == nil {
		return nil
	}

	// Extract DNS name from URI
	dnsName := extractDNSNameFromURI(*integration.Uri)

	return &apigatewayfern.LoadBalancerBackend{
		Uri:             *integration.Uri,
		VpcLinkId:       *integration.ConnectionId,
		LoadBalancerArn: "", // Would need additional API call to get actual ARN
		DnsName:         &dnsName,
	}
}

// getEndpointConfiguration converts AWS endpoint configuration to Fern EndpointType
func getEndpointConfiguration(endpointConfig *types.EndpointConfiguration) (*apigatewayfern.EndpointType, error) {
	if endpointConfig == nil || len(endpointConfig.Types) == 0 {
		return nil, nil
	}

	// Use the first endpoint type
	switch endpointConfig.Types[0] {
	case types.EndpointTypeEdge:
		endpointType := apigatewayfern.EndpointTypeEdge
		return &endpointType, nil
	case types.EndpointTypeRegional:
		endpointType := apigatewayfern.EndpointTypeRegional
		return &endpointType, nil
	case types.EndpointTypePrivate:
		endpointType := apigatewayfern.EndpointTypePrivate
		return &endpointType, nil
	default:
		return nil, fmt.Errorf("unsupported endpoint type: %s", endpointConfig.Types[0])
	}
}

// getAPICertificates retrieves domain name certificates for the API
func getAPICertificates(ctx context.Context, client *apigateway.Client) ([]*apigatewayfern.Certificate, []string) {
	log := svc1log.FromContext(ctx)
	var certificates []*apigatewayfern.Certificate
	var errors []string

	// Get domain names associated with the API with pagination
	var allDomains []types.DomainName
	domainPaginator := apigateway.NewGetDomainNamesPaginator(client, &apigateway.GetDomainNamesInput{})
	for domainPaginator.HasMorePages() {
		page, err := domainPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to get domain names",
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("GetDomainNames failed: %s", err.Error()))
			break
		}
		allDomains = append(allDomains, page.Items...)
	}

	for _, domain := range allDomains {
		if domain.CertificateArn != nil {
			cert := &apigatewayfern.Certificate{
				Arn:        *domain.CertificateArn,
				DomainName: domain.DomainName,
			}

			// Convert security policy if present
			if domain.SecurityPolicy != "" {
				switch domain.SecurityPolicy {
				case types.SecurityPolicyTls10:
					policy := apigatewayfern.SecurityPolicyTls10
					cert.SecurityPolicy = &policy
				case types.SecurityPolicyTls12:
					policy := apigatewayfern.SecurityPolicyTls12
					cert.SecurityPolicy = &policy
				}
			}

			certificates = append(certificates, cert)
		}
	}

	return certificates, errors
}

// getAPIKeysAndUsagePlans retrieves API keys and usage plans associated with the API
func getAPIKeysAndUsagePlans(ctx context.Context, client *apigateway.Client, apiID string) ([]string, []string, []string) {
	log := svc1log.FromContext(ctx)
	var apiKeys []string
	var usagePlans []string
	var errors []string

	// Get API keys with pagination
	keysPaginator := apigateway.NewGetApiKeysPaginator(client, &apigateway.GetApiKeysInput{})
	for keysPaginator.HasMorePages() {
		page, err := keysPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to get API keys",
				svc1log.SafeParam("apiId", apiID),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("GetApiKeys failed: %s", err.Error()))
			break
		}
		for _, key := range page.Items {
			if key.Id != nil {
				apiKeys = append(apiKeys, *key.Id)
			}
		}
	}

	// Get usage plans with pagination
	plansPaginator := apigateway.NewGetUsagePlansPaginator(client, &apigateway.GetUsagePlansInput{})
	for plansPaginator.HasMorePages() {
		page, err := plansPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to get usage plans",
				svc1log.SafeParam("apiId", apiID),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("GetUsagePlans failed: %s", err.Error()))
			break
		}
		for _, plan := range page.Items {
			if plan.Id != nil && plan.ApiStages != nil {
				for _, apiStage := range plan.ApiStages {
					if apiStage.ApiId != nil && *apiStage.ApiId == apiID {
						usagePlans = append(usagePlans, *plan.Id)
						break
					}
				}
			}
		}
	}

	return apiKeys, usagePlans, errors
}

// getAccessLogSettings converts stage access log settings
func getAccessLogSettings(stage types.Stage) (*apigatewayfern.AccessLogSettings, error) {
	if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
		return nil, nil
	}

	settings := &apigatewayfern.AccessLogSettings{
		DestinationArn: *stage.AccessLogSettings.DestinationArn,
		Format:         stage.AccessLogSettings.Format,
	}

	return settings, nil
}

package apigateway

import (
	"context"
	"fmt"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/Method-Security/methodaws/utils"
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
			if aws.ToString(api.Id) == "" {
				log.Warn("REST API ID is missing, skipping API", svc1log.SafeParam("region", region))
				errors = append(errors, "REST API ID is missing")
				continue
			}

			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				log.Warn("Failed to get stages for API",
					svc1log.SafeParam("region", region),
					svc1log.SafeParam("apiId", *api.Id),
					svc1log.Stacktrace(err))
				errors = append(errors, fmt.Sprintf("GetStages failed for API %s: %s", *api.Id, err.Error()))
			} else if stages == nil {
				errors = append(errors, fmt.Sprintf("GetStages returned no response for API %s", *api.Id))
			}

			var apiStages []types.Stage
			if stages != nil {
				apiStages = stages.Item
			}
			apiGw, errs := convertV1RestAPIToFern(ctx, client, api, apiStages, region)
			if apiGw != nil {
				apiGateways = append(apiGateways, apiGw)
			}
			for _, err := range errs {
				errors = append(errors, fmt.Sprintf("API %s: %s", *api.Id, err))
			}
		}
	}

	return apiGateways, errors
}

// convertV1RestAPIToFern converts AWS REST API to Fern RestApiGateway struct
func convertV1RestAPIToFern(ctx context.Context, client *apigateway.Client, api types.RestApi, stages []types.Stage, region string) (*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var errors []string

	if aws.ToString(api.Id) == "" {
		return nil, []string{"REST API ID is missing"}
	}
	apiARN, err := utils.BuildRegionalARN(region, "apigateway", "", "/restapis/"+*api.Id)
	if err != nil {
		return nil, []string{fmt.Sprintf("Failed to build REST API ARN for API %s: %s", *api.Id, err)}
	}
	stageResources, stageErrors := restAPIStages(apiARN, stages)
	errors = append(errors, stageErrors...)

	// Get resources and methods with security info
	routes, routesComplete, routeErrors := getRestAPIRoutes(ctx, client, *api.Id, region)
	errors = append(errors, routeErrors...)

	// Get endpoint configuration (not used in simplified version)
	_, err = getEndpointConfiguration(api.EndpointConfiguration)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Endpoint configuration parsing failed for API %s: %s", *api.Id, err.Error()))
	}

	// Get certificates
	certificates, errs := getAPICertificates(ctx, client, *api.Id)
	for _, err := range errs {
		log.Warn("Certificate retrieval error",
			svc1log.SafeParam("apiId", *api.Id),
			svc1log.SafeParam("error", err))
		errors = append(errors, fmt.Sprintf("Certificate retrieval failed for API %s: %s", *api.Id, err))
	}

	// A single stage supplies an unambiguous API-level invocation URL.
	var baseURL *string
	if len(stages) == 1 && len(stageResources) == 1 {
		suffix, suffixErr := utils.AWSDNSSuffixForRegion(region)
		if suffixErr != nil {
			errors = append(errors, suffixErr.Error())
		} else {
			baseURL = aws.String(fmt.Sprintf("https://%s.execute-api.%s.%s/%s", *api.Id, region, suffix, stageResources[0].Identification.Name))
		}
	}

	// Discover resource relationships
	// Resources are now nested within routes, no need for separate discovery

	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, nil)
	if securityAnalysis != nil && !routesComplete && !aws.ToBool(securityAnalysis.ApiKeysRequired) {
		securityAnalysis.ApiKeysRequired = nil
	}

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Arn:    apiARN,
		Id:     *api.Id,
		Name:   api.Name,
		Region: region,
		Url:    baseURL,
	}

	// Create configuration info
	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:      apigatewayfern.ApiGatewayVersionV1,
		Description:  api.Description,
		Certificates: certificates,
		Security:     securityAnalysis,
	}

	// Create resource info
	resources := &apigatewayfern.ApiGatewayResourceInfo{
		Stages: stageResources,
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
func getRestAPIRoutes(ctx context.Context, client *apigateway.Client, apiID, region string) ([]*apigatewayfern.Route, bool, []string) {
	log := svc1log.FromContext(ctx)
	var routes []*apigatewayfern.Route
	var errors []string
	// Optional integration enrichment errors do not hide method-level API key requirements.
	routesComplete := true
	vpcLinkTargets := make(map[string][]string)

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
			routesComplete = false
			break
		}
		allResources = append(allResources, page.Items...)
	}

	for _, resource := range allResources {
		if resource.Id == nil || resource.Path == nil {
			errors = append(errors, fmt.Sprintf("Resource ID or path is missing for API %s", apiID))
			routesComplete = false
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
				routesComplete = false
				continue
			}
			if method == nil {
				errors = append(errors, fmt.Sprintf("GetMethod returned no response for API %s, resource %s", apiID, *resource.Id))
				routesComplete = false
				continue
			}

			// Convert integration if present
			var integration *apigatewayfern.Integration
			var credentials *string
			if method.MethodIntegration != nil {
				credentials = method.MethodIntegration.Credentials
				integ, err := convertV1Integration(ctx, client, vpcLinkTargets, method.MethodIntegration, region)
				integration = integ
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

			resources, err := createRouteResources(integration, credentials)
			if err != nil {
				errors = append(errors, fmt.Sprintf("Invalid integration credentials for API %s, resource %s, method %s: %s",
					apiID, *resource.Id, methodName, err))
			}

			route := &apigatewayfern.Route{
				Identification: &apigatewayfern.RouteIdentificationInfo{
					Path:   *resource.Path,
					Method: methodName,
				},
				Configuration: &apigatewayfern.RouteConfigurationInfo{
					Authorization:  authType,
					ApiKeyRequired: method.ApiKeyRequired,
					IsDefaultRoute: aws.Bool(false),
				},
			}
			route.Resources = resources
			routes = append(routes, route)
		}
	}

	return routes, routesComplete, errors
}

// convertV1Integration converts AWS API Gateway integration to Fern Integration with backend structure
// Returns detailed error messages for debugging integration conversion failures
type getVpcLinkAPI interface {
	GetVpcLink(context.Context, *apigateway.GetVpcLinkInput, ...func(*apigateway.Options)) (*apigateway.GetVpcLinkOutput, error)
}

func convertV1Integration(
	ctx context.Context,
	client getVpcLinkAPI,
	vpcLinkTargets map[string][]string,
	methodIntegration *types.Integration,
	region string,
) (*apigatewayfern.Integration, error) {
	switch methodIntegration.Type {
	case types.IntegrationTypeHttp:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP integration missing URI")
		}
		if isVpcLinkIntegration(methodIntegration) {
			backend, err := createV1LoadBalancerBackend(ctx, client, vpcLinkTargets, methodIntegration)
			integration := &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{
				Backend: &apigatewayfern.VpcLinkBackend{Type: "load_balancer", LoadBalancer: backend},
			}}
			return integration, err
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
			return nil, fmt.Errorf("AWS integration missing URI")
		}

		backend, err := awsServiceBackendFromIntegrationURI(*methodIntegration.Uri)
		if err != nil {
			return nil, err
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
			backend, err := createV1LoadBalancerBackend(ctx, client, vpcLinkTargets, methodIntegration)
			integration := &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{
				Backend: &apigatewayfern.VpcLinkBackend{Type: "load_balancer", LoadBalancer: backend},
			}}
			return integration, err
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
		backend, err := lambdaBackendFromIntegrationURI(*methodIntegration.Uri)
		if err != nil {
			return nil, err
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

// isVpcLinkIntegration checks if the integration uses a VPC Link
func isVpcLinkIntegration(integration *types.Integration) bool {
	// In V1 API Gateway, VPC Link is indicated by connection type and connection ID
	return integration.ConnectionType == types.ConnectionTypeVpcLink &&
		integration.ConnectionId != nil
}

func createV1LoadBalancerBackend(
	ctx context.Context,
	client getVpcLinkAPI,
	vpcLinkTargets map[string][]string,
	integration *types.Integration,
) (*apigatewayfern.LoadBalancerBackend, error) {
	if integration.Uri == nil || integration.ConnectionId == nil {
		return nil, fmt.Errorf("VPC Link integration missing URI or connection ID")
	}
	backend := &apigatewayfern.LoadBalancerBackend{
		Uri:       *integration.Uri,
		VpcLinkId: *integration.ConnectionId,
	}

	targetARNs, ok := vpcLinkTargets[*integration.ConnectionId]
	if !ok {
		output, err := client.GetVpcLink(ctx, &apigateway.GetVpcLinkInput{VpcLinkId: integration.ConnectionId})
		if err != nil {
			return backend, fmt.Errorf("get VPC Link %s: %w", *integration.ConnectionId, err)
		}
		if output == nil || len(output.TargetArns) == 0 {
			return backend, fmt.Errorf("VPC Link %s returned no target ARNs", *integration.ConnectionId)
		}
		targetARNs = output.TargetArns
		vpcLinkTargets[*integration.ConnectionId] = targetARNs
	}
	if len(targetARNs) == 0 {
		return backend, fmt.Errorf("VPC Link %s has no target ARNs", *integration.ConnectionId)
	}

	backend.LoadBalancerArn = &targetARNs[0]
	backend.LoadBalancerArns = targetARNs
	return backend, nil
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
func getAPICertificates(ctx context.Context, client *apigateway.Client, apiID string) ([]*apigatewayfern.Certificate, []string) {
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
		if aws.ToString(domain.DomainName) == "" {
			continue
		}
		mapped := false
		mappings := apigateway.NewGetBasePathMappingsPaginator(client, &apigateway.GetBasePathMappingsInput{DomainName: domain.DomainName})
		for mappings.HasMorePages() {
			page, err := mappings.NextPage(ctx)
			if err != nil {
				errors = append(errors, fmt.Sprintf("GetBasePathMappings failed for domain %s: %s", *domain.DomainName, err))
				break
			}
			for _, mapping := range page.Items {
				if aws.ToString(mapping.RestApiId) == apiID {
					mapped = true
					break
				}
			}
			if mapped {
				break
			}
		}
		if !mapped {
			continue
		}
		certificateARN := domain.CertificateArn
		if aws.ToString(certificateARN) == "" {
			certificateARN = domain.RegionalCertificateArn
		}
		if aws.ToString(certificateARN) != "" {
			cert := &apigatewayfern.Certificate{
				Arn:        *certificateARN,
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

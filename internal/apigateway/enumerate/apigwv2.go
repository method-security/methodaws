package apigateway

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type vpcLinkBackendService string

const (
	vpcLinkBackendServiceElasticLoadBalancing vpcLinkBackendService = "elasticloadbalancing"
	vpcLinkBackendServiceServiceDiscovery     vpcLinkBackendService = "servicediscovery"
)

// enumerateV2ApiGatewaysAllRegions enumerates v2 API Gateways (HTTP APIs) across all specified regions
func enumerateV2ApiGatewaysAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v2 API Gateways in region", svc1log.SafeParam("region", region))
		apiGateways, errors := enumerateV2ApiGatewaysForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v2 API Gateways in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allAPIGateways = append(allAPIGateways, apiGateways...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v2 API Gateways in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("apiGatewayCount", len(apiGateways)))
	}

	return allAPIGateways, allErrors
}

// enumerateV2ApiGatewaysForRegion enumerates v2 API Gateways (HTTP APIs) for a specific region
func enumerateV2ApiGatewaysForRegion(ctx context.Context, cfg aws.Config, region string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	client := apigatewayv2.NewFromConfig(regionCfg)

	var apiGateways []*apigatewayfern.ApiGatewayInstance
	var errors []string

	// Manual pagination since GetApis doesn't have a built-in paginator
	var nextToken *string
	for {
		input := &apigatewayv2.GetApisInput{
			NextToken: nextToken,
		}

		result, err := client.GetApis(ctx, input)
		if err != nil {
			log.Warn("Failed to retrieve HTTP APIs",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Failed to retrieve HTTP APIs in region %s: %s", region, err.Error()))
			break
		}
		if result == nil {
			errors = append(errors, fmt.Sprintf("GetApis returned no response in region %s", region))
			break
		}

		// Process APIs sequentially
		for _, api := range result.Items {
			if aws.ToString(api.ApiId) == "" {
				log.Warn("HTTP API ID is nil", svc1log.SafeParam("api", api))
				errors = append(errors, "HTTP API ID is nil")
				continue
			}
			apiGw, errs := convertV2HttpAPIToFern(ctx, client, api, region)

			if apiGw != nil {
				apiGateways = append(apiGateways, apiGw)
			}
			errors = append(errors, errs...)
		}

		// Check if there are more pages
		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return apiGateways, errors
}

// convertV2HttpAPIToFern converts AWS HTTP API to Fern ApiGatewayInstance struct
func convertV2HttpAPIToFern(ctx context.Context, client *apigatewayv2.Client, api types.Api, region string) (*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)

	var errors []string

	if aws.ToString(api.ApiId) == "" {
		log.Warn("API Gateway API ID is nil")
		errors = append(errors, "api gateway API ID is nil")
		return nil, errors
	}

	// Get routes for this API with security info
	routes, errs := getHTTPAPIRoutes(ctx, client, *api.ApiId, region)
	errors = append(errors, errs...)

	// Convert CORS configuration
	var corsConfig *apigatewayfern.CorsConfiguration
	if api.CorsConfiguration != nil {
		corsConfig = &apigatewayfern.CorsConfiguration{
			AllowCredentials: api.CorsConfiguration.AllowCredentials,
			MaxAge:           convertInt32PtrToIntPtr(api.CorsConfiguration.MaxAge),
		}

		if api.CorsConfiguration.AllowHeaders != nil {
			corsConfig.AllowHeaders = api.CorsConfiguration.AllowHeaders
		}
		if api.CorsConfiguration.AllowMethods != nil {
			corsConfig.AllowMethods = api.CorsConfiguration.AllowMethods
		}
		if api.CorsConfiguration.AllowOrigins != nil {
			corsConfig.AllowOrigins = api.CorsConfiguration.AllowOrigins
		}
		if api.CorsConfiguration.ExposeHeaders != nil {
			corsConfig.ExposeHeaders = api.CorsConfiguration.ExposeHeaders
		}
	}

	// Get domain name certificates (similar to v1 but for HTTP API)
	certificates, errs := getHTTPAPICertificates(ctx, client, *api.ApiId)
	errors = append(errors, errs...)

	// Get stages for this API
	stages, err := getAllHTTPAPIStages(ctx, client, *api.ApiId)
	if err != nil {
		errors = append(errors, err.Error())
	}
	stageNames := httpAPIStageNames(stages)

	// Access log settings are included in the stage response already collected above.
	accessLogSettings := accessLogSettingsFromHTTPAPIStages(stages)
	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, corsConfig)

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Id:     *api.ApiId,
		Name:   api.Name,
		Region: region,
		Url:    api.ApiEndpoint,
	}

	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:           apigatewayfern.ApiGatewayVersionV2,
		Description:       api.Description,
		Stages:            stageNames,
		AccessLogSettings: accessLogSettings,
		CorsConfiguration: corsConfig,
		Certificates:      certificates,
		Security:          securityAnalysis,
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

func httpAPIStageNames(stages []types.Stage) []string {
	stageNames := make([]string, 0, len(stages))
	seen := make(map[string]struct{}, len(stages))
	for _, stage := range stages {
		if stage.StageName == nil || *stage.StageName == "" {
			continue
		}
		if _, ok := seen[*stage.StageName]; ok {
			continue
		}
		seen[*stage.StageName] = struct{}{}
		stageNames = append(stageNames, *stage.StageName)
	}
	sort.Strings(stageNames)
	return stageNames
}

// getHTTPAPIRoutes retrieves routes for an HTTP API
func getHTTPAPIRoutes(ctx context.Context, client *apigatewayv2.Client, apiID, region string) ([]*apigatewayfern.Route, []string) {
	var routes []*apigatewayfern.Route
	var errors []string

	// Get routes for the API with pagination
	var allRoutes []types.Route
	var nextToken *string
	for {
		routesResult, err := client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
			ApiId:     &apiID,
			NextToken: nextToken,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("GetRoutes failed for API %s: %s", apiID, err.Error()))
			break
		}
		if routesResult == nil {
			errors = append(errors, fmt.Sprintf("GetRoutes returned no response for API %s", apiID))
			break
		}
		allRoutes = append(allRoutes, routesResult.Items...)
		if routesResult.NextToken == nil {
			break
		}
		nextToken = routesResult.NextToken
	}

	for _, route := range allRoutes {
		if route.RouteKey == nil {
			errors = append(errors, fmt.Sprintf("Route key is missing for API %s", apiID))
			continue
		}
		// Get integration for this route if it exists
		var integration *apigatewayfern.Integration
		if route.Target != nil {
			// Extract integration ID from target (format: "integrations/{integrationId}")
			if len(*route.Target) > len("integrations/") {
				integrationID := (*route.Target)[len("integrations/"):]
				integrationResult, err := client.GetIntegration(ctx, &apigatewayv2.GetIntegrationInput{
					ApiId:         &apiID,
					IntegrationId: &integrationID,
				})
				if err != nil {
					errors = append(errors, err.Error())
				} else if integrationResult == nil {
					errors = append(errors, fmt.Sprintf("GetIntegration returned no response for API %s", apiID))
				} else {
					integ, err := convertV2Integration(integrationResult, region)
					if err != nil {
						errors = append(errors, err.Error())
					} else {
						integration = integ
					}
				}
			}
		}

		// Parse method and path from route key (e.g., "GET /users/{id}")
		routeKey := *route.RouteKey
		method := ""
		path := routeKey

		parts := strings.SplitN(routeKey, " ", 2)
		if len(parts) == 2 {
			method = parts[0]
			path = parts[1]
		}

		// Get authorization information
		var authType *apigatewayfern.AuthorizationType
		if route.AuthorizationType != "" {
			switch route.AuthorizationType {
			case types.AuthorizationTypeNone:
				authTypeValue := apigatewayfern.AuthorizationTypeNone
				authType = &authTypeValue
			case types.AuthorizationTypeAwsIam:
				authTypeValue := apigatewayfern.AuthorizationTypeAwsIam
				authType = &authTypeValue
			case types.AuthorizationTypeJwt:
				authTypeValue := apigatewayfern.AuthorizationTypeJwt
				authType = &authTypeValue
			}
		}

		// Get authorizer details if specified (simplified - not included in route)
		_ = route.AuthorizerId

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

		fernRoute := &apigatewayfern.Route{
			Identification: &apigatewayfern.RouteIdentificationInfo{
				Path:   path,
				Method: method,
			},
			Configuration: &apigatewayfern.RouteConfigurationInfo{
				Authorization: authType,
				// Note: HTTP API doesn't have API key requirement per route like REST API
			},
		}
		// Add resources if they exist
		if resources != nil && (resources.Integration != nil || resources.ExecutionRole != nil || resources.CloudWatchLog != nil) {
			fernRoute.Resources = resources
		}

		routes = append(routes, fernRoute)
	}

	return routes, errors
}

// convertV2Integration converts AWS API Gateway v2 integration to Fern Integration with backend structure
func convertV2Integration(integration *apigatewayv2.GetIntegrationOutput, region string) (*apigatewayfern.Integration, error) {
	switch integration.IntegrationType {
	case types.IntegrationTypeHttp:
		uri := aws.ToString(integration.IntegrationUri)

		// Check if this is a VPC Link integration (private load balancer)
		if integration.ConnectionType == types.ConnectionTypeVpcLink &&
			integration.ConnectionId != nil {
			backend, err := createV2VpcLinkBackend(integration)
			if err != nil {
				return nil, err
			}
			return &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}}, nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        uri,
			IsExternal: !strings.Contains(uri, ".amazonaws.com"),
		}

		return &apigatewayfern.Integration{Type: "http", Http: &apigatewayfern.HttpIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeAws:
		backend, err := awsServiceBackendFromIntegrationURI(aws.ToString(integration.IntegrationUri))
		if err != nil {
			return nil, err
		}

		return &apigatewayfern.Integration{Type: "aws", Aws: &apigatewayfern.AwsIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeHttpProxy:
		uri := aws.ToString(integration.IntegrationUri)

		// Check if this is a VPC Link integration (private load balancer)
		if integration.ConnectionType == types.ConnectionTypeVpcLink &&
			integration.ConnectionId != nil {
			backend, err := createV2VpcLinkBackend(integration)
			if err != nil {
				return nil, err
			}
			return &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}}, nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        uri,
			IsExternal: !strings.Contains(uri, ".amazonaws.com"),
		}

		return &apigatewayfern.Integration{Type: "http_proxy", HttpProxy: &apigatewayfern.HttpProxyIntegration{
			Backend: backend,
		}}, nil

	case types.IntegrationTypeAwsProxy:
		backend, err := lambdaBackendFromIntegrationURI(aws.ToString(integration.IntegrationUri))
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
		return nil, fmt.Errorf("unsupported integration type: %s", integration.IntegrationType)
	}
}

func createV2VpcLinkBackend(integration *apigatewayv2.GetIntegrationOutput) (*apigatewayfern.VpcLinkBackend, error) {
	uri := aws.ToString(integration.IntegrationUri)
	connectionID := aws.ToString(integration.ConnectionId)
	if uri == "" || connectionID == "" {
		return nil, fmt.Errorf("VPC Link integration missing URI or connection ID")
	}

	resourceARN := strings.SplitN(uri, "?", 2)[0]
	parsed, err := awsarn.Parse(resourceARN)
	if err != nil {
		return nil, fmt.Errorf("parse VPC Link integration URI %q: %w", uri, err)
	}

	switch vpcLinkBackendService(parsed.Service) {
	case vpcLinkBackendServiceElasticLoadBalancing:
		parts := strings.Split(parsed.Resource, "/")
		if len(parts) != 5 || parts[0] != "listener" || (parts[1] != "app" && parts[1] != "net") {
			return nil, fmt.Errorf("VPC Link integration URI is not an ALB or NLB listener ARN: %s", uri)
		}
		loadBalancerARN := parsed
		loadBalancerARN.Resource = strings.Join(append([]string{"loadbalancer"}, parts[1:4]...), "/")
		listenerARN := parsed.String()
		loadBalancerARNString := loadBalancerARN.String()
		return &apigatewayfern.VpcLinkBackend{
			Type: "load_balancer",
			LoadBalancer: &apigatewayfern.LoadBalancerBackend{
				Uri:              uri,
				VpcLinkId:        connectionID,
				LoadBalancerArn:  &loadBalancerARNString,
				LoadBalancerArns: []string{loadBalancerARNString},
				ListenerArn:      &listenerARN,
			},
		}, nil
	case vpcLinkBackendServiceServiceDiscovery:
		return &apigatewayfern.VpcLinkBackend{
			Type: "service_discovery",
			ServiceDiscovery: &apigatewayfern.ServiceDiscoveryBackend{
				Uri:        uri,
				VpcLinkId:  connectionID,
				ServiceArn: resourceARN,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported VPC Link integration URI service %q", parsed.Service)
	}
}

// getHTTPAPICertificates retrieves certificates for an HTTP API
type httpAPICertificateAPI interface {
	getDomainNamesAPI
	getAPIMappingsAPI
}

func getHTTPAPICertificates(ctx context.Context, client httpAPICertificateAPI, apiID string) ([]*apigatewayfern.Certificate, []string) {
	var certificates []*apigatewayfern.Certificate
	var errors []string

	allDomains, err := getAllHTTPAPIDomainNames(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
	}

	for _, domain := range allDomains {
		if domain.DomainName == nil {
			errors = append(errors, "API Gateway domain name is missing")
			continue
		}
		// Check if this domain is associated with our API
		mappings, err := getAllHTTPAPIMappings(ctx, client, *domain.DomainName)
		if err != nil {
			errors = append(errors, err.Error())
		}

		// Check if any mapping is for our API
		for _, mapping := range mappings {
			if mapping.ApiId != nil && *mapping.ApiId == apiID {
				if len(domain.DomainNameConfigurations) == 0 || domain.DomainNameConfigurations[0].CertificateArn == nil {
					errors = append(errors, fmt.Sprintf("Domain %s has no certificate configuration", aws.ToString(domain.DomainName)))
					break
				}

				cert := &apigatewayfern.Certificate{
					Arn:        *domain.DomainNameConfigurations[0].CertificateArn,
					DomainName: domain.DomainName,
				}

				// Convert security policy
				if domain.DomainNameConfigurations[0].SecurityPolicy != "" {
					switch domain.DomainNameConfigurations[0].SecurityPolicy {
					case types.SecurityPolicyTls10:
						policy := apigatewayfern.SecurityPolicyTls10
						cert.SecurityPolicy = &policy
					case types.SecurityPolicyTls12:
						policy := apigatewayfern.SecurityPolicyTls12
						cert.SecurityPolicy = &policy
					}
				}

				certificates = append(certificates, cert)
				break
			}
		}
	}

	return certificates, errors
}

// getHTTPAPIAccessLogSettings retrieves access log configuration
func getHTTPAPIAccessLogSettings(ctx context.Context, client getStagesAPI, apiID string) (*apigatewayfern.AccessLogSettings, error) {
	stages, err := getAllHTTPAPIStages(ctx, client, apiID)
	return accessLogSettingsFromHTTPAPIStages(stages), err
}

func accessLogSettingsFromHTTPAPIStages(stages []types.Stage) *apigatewayfern.AccessLogSettings {
	// Look for access log settings in any stage (typically $default)
	for _, stage := range stages {
		if stage.AccessLogSettings != nil && stage.AccessLogSettings.DestinationArn != nil {
			return &apigatewayfern.AccessLogSettings{
				DestinationArn: *stage.AccessLogSettings.DestinationArn,
				Format:         stage.AccessLogSettings.Format,
			}
		}
	}

	return nil
}

type getStagesAPI interface {
	GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
}

func getAllHTTPAPIStages(ctx context.Context, client getStagesAPI, apiID string) ([]types.Stage, error) {
	var stages []types.Stage
	var nextToken *string
	for {
		output, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: &apiID, NextToken: nextToken})
		if err != nil {
			return stages, fmt.Errorf("GetStages failed for API %s: %w", apiID, err)
		}
		if output == nil {
			return stages, fmt.Errorf("GetStages returned no response for API %s", apiID)
		}
		stages = append(stages, output.Items...)
		if output.NextToken == nil {
			return stages, nil
		}
		nextToken = output.NextToken
	}
}

type getDomainNamesAPI interface {
	GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error)
}

func getAllHTTPAPIDomainNames(ctx context.Context, client getDomainNamesAPI) ([]types.DomainName, error) {
	var domains []types.DomainName
	var nextToken *string
	for {
		output, err := client.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: nextToken})
		if err != nil {
			return domains, fmt.Errorf("GetDomainNames failed: %w", err)
		}
		if output == nil {
			return domains, fmt.Errorf("GetDomainNames returned no response")
		}
		domains = append(domains, output.Items...)
		if output.NextToken == nil {
			return domains, nil
		}
		nextToken = output.NextToken
	}
}

type getAPIMappingsAPI interface {
	GetApiMappings(context.Context, *apigatewayv2.GetApiMappingsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApiMappingsOutput, error)
}

func getAllHTTPAPIMappings(ctx context.Context, client getAPIMappingsAPI, domainName string) ([]types.ApiMapping, error) {
	var mappings []types.ApiMapping
	var nextToken *string
	for {
		output, err := client.GetApiMappings(ctx, &apigatewayv2.GetApiMappingsInput{
			DomainName: &domainName,
			NextToken:  nextToken,
		})
		if err != nil {
			return mappings, fmt.Errorf("GetApiMappings failed for domain %s: %w", domainName, err)
		}
		if output == nil {
			return mappings, fmt.Errorf("GetApiMappings returned no response for domain %s", domainName)
		}
		mappings = append(mappings, output.Items...)
		if output.NextToken == nil {
			return mappings, nil
		}
		nextToken = output.NextToken
	}
}

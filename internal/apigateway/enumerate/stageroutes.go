package apigateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	v1types "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	v2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

type restStageExportAPI interface {
	getVpcLinkAPI
	GetExport(context.Context, *apigateway.GetExportInput, ...func(*apigateway.Options)) (*apigateway.GetExportOutput, error)
}

type httpStageExportAPI interface {
	ExportApi(context.Context, *apigatewayv2.ExportApiInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.ExportApiOutput, error)
}

func collectRESTStageRoutes(ctx context.Context, client restStageExportAPI, apiID, region string, stages []*apigatewayfern.Stage) []string {
	var errors []string
	vpcLinkTargets := make(map[string][]string)
	for _, stage := range stages {
		output, err := client.GetExport(ctx, &apigateway.GetExportInput{
			RestApiId: aws.String(apiID), StageName: aws.String(stage.Identification.Name),
			ExportType: aws.String("oas30"), Accepts: aws.String("application/json"),
			Parameters: map[string]string{"extensions": "integrations,authorizers"},
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Export routes for stage %s: %s", stage.Identification.Arn, err))
			continue
		}
		if output == nil {
			errors = append(errors, fmt.Sprintf("Export routes for stage %s returned no response", stage.Identification.Arn))
			continue
		}
		errors = append(errors, populateStageRoutes(stage, output.Body, func(integration exportedIntegration) (*apigatewayfern.Integration, error) {
			if integration.IntegrationTarget != "" && integration.ConnectionType == "VPC_LINK" {
				return exportedListenerIntegration(integration)
			}
			return convertV1Integration(ctx, client, vpcLinkTargets, &v1types.Integration{
				Type: v1types.IntegrationType(strings.ToUpper(integration.Type)), Uri: aws.String(integration.URI),
				ConnectionType: v1types.ConnectionType(integration.ConnectionType), ConnectionId: aws.String(integration.ConnectionID),
			}, region)
		})...)
	}
	return errors
}

func collectHTTPStageRoutes(ctx context.Context, client httpStageExportAPI, apiID, region string, stages []*apigatewayfern.Stage) []string {
	var errors []string
	for _, stage := range stages {
		output, err := client.ExportApi(ctx, &apigatewayv2.ExportApiInput{
			ApiId: aws.String(apiID), StageName: aws.String(stage.Identification.Name),
			Specification: aws.String("OAS30"), OutputType: aws.String("JSON"), IncludeExtensions: aws.Bool(true),
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Export routes for stage %s: %s", stage.Identification.Arn, err))
			continue
		}
		if output == nil {
			errors = append(errors, fmt.Sprintf("Export routes for stage %s returned no response", stage.Identification.Arn))
			continue
		}
		errors = append(errors, populateStageRoutes(stage, output.Body, func(integration exportedIntegration) (*apigatewayfern.Integration, error) {
			if integration.IntegrationSubtype != "" {
				return nil, fmt.Errorf("Unsupported exported AWS service integration subtype %q", integration.IntegrationSubtype)
			}
			return convertV2Integration(&apigatewayv2.GetIntegrationOutput{
				IntegrationType: v2types.IntegrationType(strings.ToUpper(integration.Type)), IntegrationUri: aws.String(integration.URI),
				ConnectionType: v2types.ConnectionType(integration.ConnectionType), ConnectionId: aws.String(integration.ConnectionID),
			}, region)
		})...)
	}
	return errors
}

type exportedAPI struct {
	OpenAPI    string                                `json:"openapi"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Security   []map[string][]string                 `json:"security"`
	Servers    []exportedServer                      `json:"servers"`
	Components struct {
		Integrations    map[string]json.RawMessage        `json:"x-amazon-apigateway-integrations"`
		SecuritySchemes map[string]exportedSecurityScheme `json:"securitySchemes"`
	} `json:"components"`
}

type exportedServer struct {
	URL       string `json:"url"`
	Variables map[string]struct {
		Default *string `json:"default"`
	} `json:"variables"`
}

type exportedOperation struct {
	IsDefaultRoute bool                   `json:"isDefaultRoute"`
	Security       *[]map[string][]string `json:"security"`
	Integration    json.RawMessage        `json:"x-amazon-apigateway-integration"`
}

type exportedIntegration struct {
	Ref                string `json:"$ref"`
	Type               string `json:"type"`
	URI                string `json:"uri"`
	Credentials        string `json:"credentials"`
	ConnectionType     string `json:"connectionType"`
	ConnectionID       string `json:"connectionId"`
	IntegrationTarget  string `json:"integrationTarget"`
	IntegrationSubtype string `json:"integrationSubtype"`
}

type exportedSecurityScheme struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	In         string `json:"in"`
	AuthType   string `json:"x-amazon-apigateway-authtype"`
	Authorizer struct {
		Type string `json:"type"`
	} `json:"x-amazon-apigateway-authorizer"`
}

type exportedIntegrationConverter func(exportedIntegration) (*apigatewayfern.Integration, error)

func populateStageRoutes(stage *apigatewayfern.Stage, body []byte, convert exportedIntegrationConverter) []string {
	var document exportedAPI
	if err := json.Unmarshal(body, &document); err != nil {
		return []string{fmt.Sprintf("Decode route export for stage %s: %s", stage.Identification.Arn, err)}
	}
	if !strings.HasPrefix(document.OpenAPI, "3.") || document.Paths == nil {
		return []string{fmt.Sprintf("Stage %s export is missing an OpenAPI 3 paths object", stage.Identification.Arn)}
	}
	var errors []string
	stageURL, err := exportedStageURL(document.Servers)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Stage %s URL: %s", stage.Identification.Arn, err))
	}
	stage.Identification.Url = stageURL
	routes := make([]*apigatewayfern.Route, 0)
	paths := make([]string, 0, len(document.Paths))
	for path := range document.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		item := document.Paths[path]
		if !strings.HasPrefix(path, "/") || item == nil || item["$ref"] != nil {
			errors = append(errors, fmt.Sprintf("Stage %s has an invalid or referenced exported path %q", stage.Identification.Arn, path))
			continue
		}
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace", "connect", "x-amazon-apigateway-any-method"} {
			payload, exists := item[method]
			if !exists {
				continue
			}
			var operation *exportedOperation
			if err := json.Unmarshal(payload, &operation); err != nil || operation == nil {
				errors = append(errors, fmt.Sprintf("Stage %s has an invalid exported operation %s %s", stage.Identification.Arn, method, path))
				continue
			}
			route, errs := document.route(path, method, *operation, stage.Configuration.Variables, convert)
			for _, err := range errs {
				errors = append(errors, fmt.Sprintf("Stage %s route %s %s: %s", stage.Identification.Arn, method, path, err))
			}
			routes = append(routes, route)
		}
	}
	if stage.Resources == nil {
		stage.Resources = &apigatewayfern.StageResourceInfo{}
	}
	stage.Resources.Routes = routes
	return errors
}

func (document exportedAPI) route(path, method string, operation exportedOperation, variables map[string]string, convert exportedIntegrationConverter) (*apigatewayfern.Route, []string) {
	method = strings.ToUpper(method)
	if method == "X-AMAZON-APIGATEWAY-ANY-METHOD" {
		method = "ANY"
	}
	if operation.IsDefaultRoute {
		path, method = "$default", ""
	}
	route := &apigatewayfern.Route{
		Identification: &apigatewayfern.RouteIdentificationInfo{Path: path, Method: method},
		Configuration:  &apigatewayfern.RouteConfigurationInfo{IsDefaultRoute: aws.Bool(operation.IsDefaultRoute)},
	}
	var errors []string
	security := document.Security
	if operation.Security != nil {
		security = *operation.Security
	}
	authorization, apiKey, err := document.authorization(security)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		route.Configuration.Authorization = &authorization
		route.Configuration.ApiKeyRequired = &apiKey
	}
	integration, err := document.integration(operation.Integration, variables)
	if err != nil {
		return route, append(errors, err.Error())
	}
	backend, err := convert(*integration)
	if err != nil {
		errors = append(errors, err.Error())
		backend = nil
	}
	route.Resources, err = createRouteResources(backend, aws.String(integration.Credentials))
	if err != nil {
		errors = append(errors, err.Error())
	}
	return route, errors
}

func (document exportedAPI) integration(payload json.RawMessage, variables map[string]string) (*exportedIntegration, error) {
	seen := make(map[string]bool)
	for {
		var integration exportedIntegration
		if err := json.Unmarshal(payload, &integration); err != nil || integration.Type == "" && integration.Ref == "" {
			return nil, fmt.Errorf("Missing or invalid exported integration")
		}
		if integration.Ref != "" {
			const prefix = "#/components/x-amazon-apigateway-integrations/"
			if !strings.HasPrefix(integration.Ref, prefix) || seen[integration.Ref] {
				return nil, fmt.Errorf("Unsupported or cyclic exported integration reference %q", integration.Ref)
			}
			seen[integration.Ref] = true
			key := strings.NewReplacer("~1", "/", "~0", "~").Replace(strings.TrimPrefix(integration.Ref, prefix))
			payload = document.Components.Integrations[key]
			continue
		}
		for _, value := range []*string{&integration.URI, &integration.Credentials, &integration.ConnectionID, &integration.IntegrationTarget} {
			resolved, err := resolveStageVariables(*value, variables)
			if err != nil {
				return nil, err
			}
			*value = resolved
		}
		if !strings.EqualFold(integration.Type, "mock") && integration.URI == "" {
			return nil, fmt.Errorf("Exported integration is missing its URI")
		}
		if integration.ConnectionType == "VPC_LINK" && integration.ConnectionID == "" {
			return nil, fmt.Errorf("Exported VPC Link integration is missing its connection ID")
		}
		return &integration, nil
	}
}

func resolveStageVariables(value string, variables map[string]string) (string, error) {
	var result strings.Builder
	for {
		before, after, found := strings.Cut(value, "${stageVariables.")
		result.WriteString(before)
		if !found {
			break
		}
		name, remaining, closed := strings.Cut(after, "}")
		replacement, exists := variables[name]
		if !closed || !exists {
			return "", fmt.Errorf("Cannot resolve exported integration stage variable %q", name)
		}
		result.WriteString(replacement)
		value = remaining
	}
	if strings.Contains(result.String(), "${") {
		return "", fmt.Errorf("Exported integration contains an unresolved variable")
	}
	return result.String(), nil
}

func (document exportedAPI) authorization(security []map[string][]string) (apigatewayfern.AuthorizationType, bool, error) {
	authorization := apigatewayfern.AuthorizationTypeNone
	apiKey := false
	if len(security) > 1 {
		return authorization, false, fmt.Errorf("Exported alternative security requirements cannot be represented as one authorization setting")
	}
	for _, requirement := range security {
		for name := range requirement {
			scheme, exists := document.Components.SecuritySchemes[name]
			if !exists {
				return authorization, false, fmt.Errorf("Exported security scheme %q is missing", name)
			}
			var kind apigatewayfern.AuthorizationType
			switch {
			case strings.EqualFold(scheme.AuthType, "awsSigv4"):
				kind = apigatewayfern.AuthorizationTypeAwsIam
			case strings.EqualFold(scheme.Authorizer.Type, "jwt"):
				kind = apigatewayfern.AuthorizationTypeJwt
			case strings.EqualFold(scheme.Authorizer.Type, "cognito_user_pools"):
				kind = apigatewayfern.AuthorizationTypeCognitoUserPools
			case strings.EqualFold(scheme.Authorizer.Type, "token"), strings.EqualFold(scheme.Authorizer.Type, "request"):
				kind = apigatewayfern.AuthorizationTypeCustom
			case scheme.Type == "apiKey" && strings.EqualFold(scheme.Name, "x-api-key") && scheme.In == "header" && scheme.AuthType == "" && scheme.Authorizer.Type == "":
				apiKey = true
				continue
			default:
				return authorization, false, fmt.Errorf("Unsupported exported security scheme %q", name)
			}
			if authorization != apigatewayfern.AuthorizationTypeNone && authorization != kind {
				return authorization, false, fmt.Errorf("Exported route has multiple authorization mechanisms")
			}
			authorization = kind
		}
	}
	return authorization, apiKey, nil
}

func exportedStageURL(servers []exportedServer) (*string, error) {
	if len(servers) != 1 {
		return nil, nil
	}
	server := servers[0]
	value := server.URL
	for name, variable := range server.Variables {
		if variable.Default != nil {
			value = strings.ReplaceAll(value, "{"+name+"}", *variable.Default)
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || strings.ContainsAny(value, "{}") {
		return nil, fmt.Errorf("Exported server does not identify a concrete HTTP URL")
	}
	return &value, nil
}

func exportedListenerIntegration(integration exportedIntegration) (*apigatewayfern.Integration, error) {
	backend, err := createV2VpcLinkBackend(&apigatewayv2.GetIntegrationOutput{
		IntegrationUri: aws.String(integration.IntegrationTarget), ConnectionId: aws.String(integration.ConnectionID),
	})
	if err != nil {
		return nil, err
	}
	return &apigatewayfern.Integration{Type: "vpc_link", VpcLink: &apigatewayfern.VpcLinkIntegration{Backend: backend}}, nil
}

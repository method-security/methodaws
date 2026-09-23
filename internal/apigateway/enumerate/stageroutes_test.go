package apigateway

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	v1types "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	v2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stageExportClient struct {
	bodies map[string]string
	calls  []string
}

func (s *stageExportClient) body(name string) ([]byte, error) {
	s.calls = append(s.calls, name)
	if body, exists := s.bodies[name]; exists {
		return []byte(body), nil
	}
	return nil, fmt.Errorf("access denied for stage %s", name)
}

func (s *stageExportClient) GetExport(_ context.Context, input *apigateway.GetExportInput, _ ...func(*apigateway.Options)) (*apigateway.GetExportOutput, error) {
	if aws.ToString(input.ExportType) != "oas30" || input.Parameters["extensions"] != "integrations,authorizers" {
		return nil, fmt.Errorf("missing OpenAPI format or extensions")
	}
	body, err := s.body(aws.ToString(input.StageName))
	return &apigateway.GetExportOutput{Body: body}, err
}

func (s *stageExportClient) GetVpcLink(_ context.Context, _ *apigateway.GetVpcLinkInput, _ ...func(*apigateway.Options)) (*apigateway.GetVpcLinkOutput, error) {
	return &apigateway.GetVpcLinkOutput{TargetArns: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/orders/abc"}}, nil
}

func (s *stageExportClient) ExportApi(_ context.Context, input *apigatewayv2.ExportApiInput, _ ...func(*apigatewayv2.Options)) (*apigatewayv2.ExportApiOutput, error) {
	if aws.ToString(input.Specification) != "OAS30" || aws.ToString(input.OutputType) != "JSON" || !aws.ToBool(input.IncludeExtensions) {
		return nil, fmt.Errorf("missing OpenAPI format or extensions")
	}
	body, err := s.body(aws.ToString(input.StageName))
	return &apigatewayv2.ExportApiOutput{Body: body}, err
}

func TestRESTStageRoutesKeepDeployedMembershipAndBackends(t *testing.T) {
	stages, errs := restAPIStages("arn:aws:apigateway:us-east-1::/restapis/abc", []v1types.Stage{
		{StageName: aws.String("prod"), WebAclArn: aws.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod/id")},
		{StageName: aws.String("dev")},
		{StageName: aws.String("denied")},
	})
	require.Empty(t, errs)
	client := &stageExportClient{bodies: map[string]string{
		"prod": `{"openapi":"3.0.1","servers":[{"url":"https://abc.execute-api.us-east-1.amazonaws.com/{basePath}","variables":{"basePath":{"default":"prod"}}}],"paths":{
			"/users":{"get":{"x-amazon-apigateway-integration":{"type":"aws_proxy","uri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:prod/invocations","credentials":"arn:aws:iam::123456789012:role/prod"}}}}}`,
		"dev": `{"openapi":"3.0.1","paths":{
			"/users":{"get":{"x-amazon-apigateway-integration":{"type":"http_proxy","uri":"https://dev.example.com/users"}}},
			"/admin":{"delete":{"x-amazon-apigateway-integration":{"type":"mock"}}}}}`,
	}}
	errs = collectRESTStageRoutes(context.Background(), client, "abc", "us-east-1", stages)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "denied")
	assert.Equal(t, []string{"denied", "dev", "prod"}, client.calls)
	assert.Nil(t, stages[0].Resources)
	require.Len(t, stages[1].Resources.Routes, 2)
	assert.Equal(t, "/admin", stages[1].Resources.Routes[0].Identification.Path)
	assert.Equal(t, "https://dev.example.com/users", stages[1].Resources.Routes[1].Resources.Integration.HttpProxy.Backend.Uri)
	prod := stages[2]
	require.Len(t, prod.Resources.Routes, 1)
	assert.Equal(t, "https://abc.execute-api.us-east-1.amazonaws.com/prod", *prod.Identification.Url)
	assert.Equal(t, "/users", prod.Resources.Routes[0].Identification.Path)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:prod", prod.Resources.Routes[0].Resources.Integration.AwsProxy.Backend.Arn)
	assert.Equal(t, "arn:aws:iam::123456789012:role/prod", prod.Resources.Routes[0].Resources.ExecutionRole.Arn)
	assert.NotNil(t, prod.Resources.WebAcl)
	payload, err := json.Marshal(prod)
	require.NoError(t, err)
	var signal map[string]any
	require.NoError(t, json.Unmarshal(payload, &signal))
	assert.Contains(t, signal["resources"], "routes")
}

func TestHTTPStageRoutesUseExportedReferencesAndStageVariables(t *testing.T) {
	stages, errs := httpAPIStages("arn:aws:apigateway:us-east-1::/apis/abc", []v2types.Stage{
		{StageName: aws.String("$default"), StageVariables: map[string]string{"function": "orders"}},
	})
	require.Empty(t, errs)
	client := &stageExportClient{bodies: map[string]string{"$default": `{
		"openapi":"3.0.1",
		"paths":{
			"/$default":{"x-amazon-apigateway-any-method":{"isDefaultRoute":true,"security":[],"x-amazon-apigateway-integration":{"$ref":"#/components/x-amazon-apigateway-integrations/default"}}},
			"/users/{id}":{"x-amazon-apigateway-any-method":{"x-amazon-apigateway-integration":{"type":"http_proxy","connectionType":"VPC_LINK","connectionId":"vpc-123","uri":"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/orders/abc/def"}}}
		},
		"security":[{"sigv4":[]}],
		"components":{
			"securitySchemes":{"sigv4":{"type":"apiKey","x-amazon-apigateway-authtype":"awsSigv4"}},
			"x-amazon-apigateway-integrations":{"default":{"type":"AWS_PROXY","uri":"arn:aws:lambda:us-east-1:123456789012:function:${stageVariables.function}"}}
		}
	}`}}
	errs = collectHTTPStageRoutes(context.Background(), client, "abc", "us-east-1", stages)
	require.Empty(t, errs)
	assert.Equal(t, []string{"$default"}, client.calls)
	routes := stages[0].Resources.Routes
	require.Len(t, routes, 2)
	assert.Equal(t, "$default", routes[0].Identification.Path)
	assert.Empty(t, routes[0].Identification.Method)
	assert.True(t, *routes[0].Configuration.IsDefaultRoute)
	assert.Equal(t, apigatewayfern.AuthorizationTypeNone, *routes[0].Configuration.Authorization)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:orders", routes[0].Resources.Integration.AwsProxy.Backend.Arn)
	assert.Equal(t, "ANY", routes[1].Identification.Method)
	assert.Equal(t, apigatewayfern.AuthorizationTypeAwsIam, *routes[1].Configuration.Authorization)
	assert.Equal(t, "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/orders/abc/def", *routes[1].Resources.Integration.VpcLink.Backend.LoadBalancer.ListenerArn)
}

func TestStageExportFailuresDoNotInventBackendLinks(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":           `{`,
		"not-export":          `{}`,
		"missing-integration": `{"openapi":"3.0.1","paths":{"/users":{"get":{}}}}`,
		"missing-variable":    `{"openapi":"3.0.1","paths":{"/users":{"get":{"x-amazon-apigateway-integration":{"type":"aws_proxy","uri":"arn:aws:lambda:us-east-1:123456789012:function:${stageVariables.missing}"}}}}}`,
		"cyclic-reference":    `{"openapi":"3.0.1","paths":{"/users":{"get":{"x-amazon-apigateway-integration":{"$ref":"#/components/x-amazon-apigateway-integrations/loop"}}}},"components":{"x-amazon-apigateway-integrations":{"loop":{"$ref":"#/components/x-amazon-apigateway-integrations/loop"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			stages, errs := httpAPIStages("arn:aws:apigateway:us-east-1::/apis/abc", []v2types.Stage{{StageName: aws.String("prod")}})
			require.Empty(t, errs)
			errs = collectHTTPStageRoutes(context.Background(), &stageExportClient{bodies: map[string]string{"prod": body}}, "abc", "us-east-1", stages)
			require.NotEmpty(t, errs)
			if stages[0].Resources != nil {
				for _, route := range stages[0].Resources.Routes {
					assert.Nil(t, route.Resources)
				}
			}
		})
	}
}

func TestExportedAuthorization(t *testing.T) {
	var document exportedAPI
	require.NoError(t, json.Unmarshal([]byte(`{"components":{"securitySchemes":{
		"iam":{"type":"apiKey","x-amazon-apigateway-authtype":"awsSigv4"},
		"key":{"type":"apiKey","name":"x-api-key","in":"header"},
		"jwt":{"type":"oauth2","x-amazon-apigateway-authorizer":{"type":"jwt"}},
		"custom":{"type":"apiKey","x-amazon-apigateway-authorizer":{"type":"request"}}
	}}}`), &document))
	for _, test := range []struct {
		schemes map[string][]string
		auth    apigatewayfern.AuthorizationType
		key     bool
	}{
		{map[string][]string{"iam": {}, "key": {}}, apigatewayfern.AuthorizationTypeAwsIam, true},
		{map[string][]string{"jwt": {}}, apigatewayfern.AuthorizationTypeJwt, false},
		{map[string][]string{"custom": {}}, apigatewayfern.AuthorizationTypeCustom, false},
	} {
		auth, key, err := document.authorization([]map[string][]string{test.schemes})
		require.NoError(t, err)
		assert.Equal(t, test.auth, auth)
		assert.Equal(t, test.key, key)
	}
}

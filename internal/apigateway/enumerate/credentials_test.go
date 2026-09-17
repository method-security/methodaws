package apigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutionRoleFromCredentials(t *testing.T) {
	for _, partition := range []string{"aws", "aws-us-gov", "aws-cn"} {
		arn := "arn:" + partition + ":iam::123456789012:role/service-role/gateway-invoke"
		role, err := executionRoleFromCredentials(arn)
		require.NoError(t, err)
		require.NotNil(t, role)
		assert.Equal(t, arn, role.Arn)
		assert.Equal(t, "gateway-invoke", aws.ToString(role.RoleName))

		role, err = executionRoleFromCredentials("arn:" + partition + ":iam::*:user/*")
		require.NoError(t, err)
		assert.Nil(t, role)
	}
	for _, value := range []string{
		"not-an-arn",
		"arn:aws:lambda:us-east-1:123456789012:function:backend",
		"arn:aws:iam::123456789012:user/caller",
		"arn:aws:iam::123456789012:role/",
		"arn:aws:iam::*:role/invoke",
		"arn:aws:iam::123456789012:role/*",
		"arn:aws:iam:us-east-1:123456789012:role/invoke",
	} {
		role, err := executionRoleFromCredentials(value)
		require.Error(t, err, value)
		assert.Nil(t, role)
	}
	resources, err := createRouteResources(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, resources)
	resources, err = createRouteResources(nil, aws.String("arn:aws:iam::123456789012:role/invoke"))
	require.NoError(t, err)
	require.NotNil(t, resources.ExecutionRole)
	assert.Nil(t, resources.Integration)
}

func TestRoutesUseConfiguredIntegrationCredentials(t *testing.T) {
	const roleARN = "arn:aws:iam::210987654321:role/service-role/gateway-invoke"
	const functionARN = "arn:aws:lambda:us-east-1:123456789012:function:backend"
	for _, version := range []string{"REST", "HTTP"} {
		for _, tc := range []struct {
			name        string
			credentials *string
			wantRole    bool
			wantError   bool
		}{
			{"role", aws.String(roleARN), true, false},
			{"resource policy", nil, false, false},
			{"caller passthrough", aws.String("arn:aws:iam::*:user/*"), false, false},
			{"invalid", aws.String(functionARN), false, true},
		} {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					var response any
					switch r.URL.Path {
					case "/restapis/api/resources":
						response = map[string]any{"item": []any{
							map[string]any{"id": "first", "path": "/first", "resourceMethods": map[string]any{"GET": map[string]any{}}},
							map[string]any{"id": "second", "path": "/second", "resourceMethods": map[string]any{"GET": map[string]any{}}},
						}}
					case "/v2/apis/api/routes":
						response = map[string]any{"items": []any{
							map[string]any{"routeKey": "GET /first", "target": "integrations/first"},
							map[string]any{"routeKey": "GET /second", "target": "integrations/second"},
						}}
					default:
						var credentials *string
						if strings.Contains(r.URL.Path, "/first") {
							credentials = tc.credentials
						}
						if version == "REST" {
							response = map[string]any{"methodIntegration": map[string]any{
								"type": "AWS_PROXY", "credentials": credentials,
								"uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/" + functionARN + "/invocations",
							}}
						} else {
							response = map[string]any{"integrationType": "AWS_PROXY", "integrationUri": functionARN, "credentialsArn": credentials}
						}
					}
					assert.NoError(t, json.NewEncoder(w).Encode(response))
				}))
				defer server.Close()
				cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(server.URL)}
				var routes []*apigatewayfern.Route
				var errs []string
				if version == "REST" {
					var complete bool
					routes, complete, errs = getRestAPIRoutes(context.Background(), apigateway.NewFromConfig(cfg), "api", "us-east-1")
					assert.True(t, complete)
				} else {
					routes, errs = getHTTPAPIRoutes(context.Background(), apigatewayv2.NewFromConfig(cfg), "api", "us-east-1")
				}
				if tc.wantError {
					require.Len(t, errs, 1)
					assert.Contains(t, errs[0], "Invalid integration credentials for API api")
				} else {
					require.Empty(t, errs)
				}
				require.Len(t, routes, 2)
				for _, route := range routes {
					require.NotNil(t, route.Resources)
					require.NotNil(t, route.Resources.Integration)
					assert.Equal(t, functionARN, route.Resources.Integration.AwsProxy.Backend.Arn)
					if tc.wantRole && route.Identification.Path == "/first" {
						require.NotNil(t, route.Resources.ExecutionRole)
						assert.Equal(t, roleARN, route.Resources.ExecutionRole.Arn)
					} else {
						assert.Nil(t, route.Resources.ExecutionRole)
					}
				}
			})
		}
	}
}

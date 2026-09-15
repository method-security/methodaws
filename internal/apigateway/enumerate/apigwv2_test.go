package apigateway

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubAPIGatewayV2PaginationClient struct {
	stageOutputs   []*apigatewayv2.GetStagesOutput
	domainOutputs  []*apigatewayv2.GetDomainNamesOutput
	mappingOutputs []*apigatewayv2.GetApiMappingsOutput
	stageTokens    []*string
	domainTokens   []*string
	mappingTokens  []*string
	stageErrors    []error
	domainErrors   []error
	mappingErrors  []error
}

func (s *stubAPIGatewayV2PaginationClient) GetStages(
	_ context.Context,
	input *apigatewayv2.GetStagesInput,
	_ ...func(*apigatewayv2.Options),
) (*apigatewayv2.GetStagesOutput, error) {
	s.stageTokens = append(s.stageTokens, input.NextToken)
	output := s.stageOutputs[0]
	s.stageOutputs = s.stageOutputs[1:]
	var err error
	if len(s.stageErrors) > 0 {
		err = s.stageErrors[0]
		s.stageErrors = s.stageErrors[1:]
	}
	return output, err
}

func (s *stubAPIGatewayV2PaginationClient) GetDomainNames(
	_ context.Context,
	input *apigatewayv2.GetDomainNamesInput,
	_ ...func(*apigatewayv2.Options),
) (*apigatewayv2.GetDomainNamesOutput, error) {
	s.domainTokens = append(s.domainTokens, input.NextToken)
	output := s.domainOutputs[0]
	s.domainOutputs = s.domainOutputs[1:]
	var err error
	if len(s.domainErrors) > 0 {
		err = s.domainErrors[0]
		s.domainErrors = s.domainErrors[1:]
	}
	return output, err
}

func (s *stubAPIGatewayV2PaginationClient) GetApiMappings(
	_ context.Context,
	input *apigatewayv2.GetApiMappingsInput,
	_ ...func(*apigatewayv2.Options),
) (*apigatewayv2.GetApiMappingsOutput, error) {
	s.mappingTokens = append(s.mappingTokens, input.NextToken)
	output := s.mappingOutputs[0]
	s.mappingOutputs = s.mappingOutputs[1:]
	var err error
	if len(s.mappingErrors) > 0 {
		err = s.mappingErrors[0]
		s.mappingErrors = s.mappingErrors[1:]
	}
	return output, err
}

func TestHTTPAPICallersUsePagesCollectedBeforeFailure(t *testing.T) {
	t.Parallel()

	client := &stubAPIGatewayV2PaginationClient{
		stageOutputs: []*apigatewayv2.GetStagesOutput{
			{Items: []types.Stage{{
				StageName: aws.String("prod"),
				AccessLogSettings: &types.AccessLogSettings{
					DestinationArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:api"),
				},
			}}, NextToken: aws.String("next")},
			nil,
		},
		stageErrors: []error{nil, errors.New("stage page denied")},
		domainOutputs: []*apigatewayv2.GetDomainNamesOutput{
			{Items: []types.DomainName{{
				DomainName: aws.String("api.example"),
				DomainNameConfigurations: []types.DomainNameConfiguration{{
					CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/example"),
				}},
			}}, NextToken: aws.String("next")},
			nil,
		},
		domainErrors: []error{nil, errors.New("domain page denied")},
		mappingOutputs: []*apigatewayv2.GetApiMappingsOutput{{
			Items: []types.ApiMapping{{ApiId: aws.String("api-id")}},
		}},
	}

	stages, stageErr := getAllHTTPAPIStages(context.Background(), client, "api-id")
	require.Error(t, stageErr)
	assert.Equal(t, "prod", aws.ToString(primaryHTTPAPIStage(stages)))

	settings, settingsErr := getHTTPAPIAccessLogSettings(context.Background(), &stubAPIGatewayV2PaginationClient{
		stageOutputs: []*apigatewayv2.GetStagesOutput{
			{Items: stages, NextToken: aws.String("next")}, nil,
		},
		stageErrors: []error{nil, errors.New("stage page denied")},
	}, "api-id")
	require.Error(t, settingsErr)
	require.NotNil(t, settings)

	certificates, certificateErrors := getHTTPAPICertificates(context.Background(), client, "api-id")
	require.Len(t, certificateErrors, 1)
	require.Len(t, certificates, 1)
	assert.Equal(t, "arn:aws:acm:us-east-1:123456789012:certificate/example", certificates[0].Arn)
}

func TestHTTPAPIPaginationHelpersCollectEveryPage(t *testing.T) {
	client := &stubAPIGatewayV2PaginationClient{
		stageOutputs: []*apigatewayv2.GetStagesOutput{
			{Items: []types.Stage{{StageName: aws.String("one")}}, NextToken: aws.String("stage-next")},
			{Items: []types.Stage{{StageName: aws.String("two")}}},
		},
		domainOutputs: []*apigatewayv2.GetDomainNamesOutput{
			{Items: []types.DomainName{{DomainName: aws.String("one.example")}}, NextToken: aws.String("domain-next")},
			{Items: []types.DomainName{{DomainName: aws.String("two.example")}}},
		},
		mappingOutputs: []*apigatewayv2.GetApiMappingsOutput{
			{Items: []types.ApiMapping{{ApiId: aws.String("one")}}, NextToken: aws.String("mapping-next")},
			{Items: []types.ApiMapping{{ApiId: aws.String("two")}}},
		},
	}

	stages, err := getAllHTTPAPIStages(context.Background(), client, "api-id")
	require.NoError(t, err)
	domains, err := getAllHTTPAPIDomainNames(context.Background(), client)
	require.NoError(t, err)
	mappings, err := getAllHTTPAPIMappings(context.Background(), client, "example.com")
	require.NoError(t, err)

	assert.Len(t, stages, 2)
	assert.Len(t, domains, 2)
	assert.Len(t, mappings, 2)
	assert.Equal(t, []*string{nil, aws.String("stage-next")}, client.stageTokens)
	assert.Equal(t, []*string{nil, aws.String("domain-next")}, client.domainTokens)
	assert.Equal(t, []*string{nil, aws.String("mapping-next")}, client.mappingTokens)
}

func TestHTTPAPIPaginationHelpersRejectNilResponses(t *testing.T) {
	client := &stubAPIGatewayV2PaginationClient{
		stageOutputs:   []*apigatewayv2.GetStagesOutput{nil},
		domainOutputs:  []*apigatewayv2.GetDomainNamesOutput{nil},
		mappingOutputs: []*apigatewayv2.GetApiMappingsOutput{nil},
	}

	_, err := getAllHTTPAPIStages(context.Background(), client, "api-id")
	require.EqualError(t, err, "GetStages returned no response for API api-id")
	_, err = getAllHTTPAPIDomainNames(context.Background(), client)
	require.EqualError(t, err, "GetDomainNames returned no response")
	_, err = getAllHTTPAPIMappings(context.Background(), client, "example.com")
	require.EqualError(t, err, "GetApiMappings returned no response for domain example.com")
}

func TestConvertV2VpcLinkDerivesLoadBalancerFromListener(t *testing.T) {
	t.Parallel()

	listenerARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/example/abc/def"
	backend, err := createV2VpcLinkBackend(&apigatewayv2.GetIntegrationOutput{
		ConnectionId:   aws.String("vpclink-123"),
		IntegrationUri: aws.String(listenerARN),
	})

	require.NoError(t, err)
	require.NotNil(t, backend.LoadBalancer)
	assert.Equal(t, listenerARN, aws.ToString(backend.LoadBalancer.ListenerArn))
	assert.Equal(t,
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example/abc",
		backend.LoadBalancer.LoadBalancerArn,
	)
	assert.Nil(t, backend.LoadBalancer.DnsName)
}

func TestConvertV2VpcLinkPreservesCloudMapService(t *testing.T) {
	t.Parallel()

	serviceARN := "arn:aws:servicediscovery:us-east-1:123456789012:service/srv-example"
	backend, err := createV2VpcLinkBackend(&apigatewayv2.GetIntegrationOutput{
		ConnectionId:   aws.String("vpclink-123"),
		IntegrationUri: aws.String(serviceARN + "?stage=prod"),
	})

	require.NoError(t, err)
	require.NotNil(t, backend.ServiceDiscovery)
	assert.Equal(t, serviceARN, backend.ServiceDiscovery.ServiceArn)
	assert.Equal(t, serviceARN+"?stage=prod", backend.ServiceDiscovery.Uri)
}

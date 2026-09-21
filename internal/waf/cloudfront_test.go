package waf

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubCloudFrontClient struct {
	inputs []*cloudfront.ListDistributionsByWebACLIdInput
	output *cloudfront.ListDistributionsByWebACLIdOutput
}

func (s *stubCloudFrontClient) ListDistributionsByWebACLId(_ context.Context, input *cloudfront.ListDistributionsByWebACLIdInput, _ ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsByWebACLIdOutput, error) {
	s.inputs = append(s.inputs, input)
	if len(s.inputs) > 1 {
		return nil, errors.New("second page denied")
	}
	return s.output, nil
}

func TestDistributionAssociationsRetainValidIdentitiesOnPageError(t *testing.T) {
	const parent = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/id"
	client := &stubCloudFrontClient{output: &cloudfront.ListDistributionsByWebACLIdOutput{DistributionList: &types.DistributionList{
		IsTruncated: aws.Bool(true), NextMarker: aws.String("next"),
		Items: []types.DistributionSummary{
			{ARN: aws.String("arn:aws:cloudfront::123456789012:distribution/E123"), Id: aws.String("E123"),
				WebACLId: aws.String(parent), DomainName: aws.String("example.cloudfront.net")},
			{ARN: aws.String("arn:aws:cloudfront::999999999999:distribution/E456"), Id: aws.String("E456")},
		},
	}}}
	distributions, errs := distributionsForWebACL(context.Background(), client, parent)
	require.Len(t, distributions, 1)
	assert.Equal(t, "arn:aws:cloudfront::123456789012:distribution/E123", distributions[0].Arn)
	assert.Nil(t, distributions[0].Region)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[1], "second page denied")
	require.Len(t, client.inputs, 2)
	assert.Equal(t, parent, *client.inputs[0].WebACLId)
	assert.Equal(t, "next", *client.inputs[1].Marker)
}

func TestDistributionAssociationsHandleMissingResponse(t *testing.T) {
	distributions, errs := distributionsForWebACL(context.Background(), &stubCloudFrontClient{},
		"arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/id")
	assert.Empty(t, distributions)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "returned no distribution list")
}

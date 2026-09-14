package route53

import (
	"testing"

	route53fern "github.com/Method-Security/methodaws/generated/go/route53"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceInfoDoesNotInferARNsFromDNSTargets(t *testing.T) {
	t.Parallel()

	records := []*route53fern.ResourceRecordSet{
		{
			Name: "cdn.example.com.",
			Type: route53fern.RecordTypeA,
			AliasTarget: &route53fern.AliasTarget{
				DnsName:      "d111111abcdef8.cloudfront.net.",
				HostedZoneId: "Z2FDTNDATAQYW2",
			},
		},
		{
			Name: "app.example.com.",
			Type: route53fern.RecordTypeA,
			AliasTarget: &route53fern.AliasTarget{
				DnsName:      "example.us-east-1.elb.amazonaws.com.",
				HostedZoneId: "Z35SXDOTRQ7X7K",
			},
		},
	}

	resources := resourceInfoForRecordSets(records)

	require.NotNil(t, resources)
	assert.Equal(t, records, resources.RecordSets)
	assert.Nil(t, resources.CloudFrontDistributions)
	assert.Nil(t, resources.LoadBalancers)
	assert.Nil(t, resources.S3Buckets)
}

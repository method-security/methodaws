package route53

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	route53fern "github.com/Method-Security/methodaws/generated/go/route53"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostedZoneIdentityAndNestedRecords(t *testing.T) {
	for _, tc := range []struct{ region, partition string }{
		{"us-east-1", "aws"}, {"cn-north-1", "aws-cn"}, {"us-gov-west-1", "aws-us-gov"},
	} {
		t.Run(tc.partition, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				if strings.HasSuffix(r.URL.Path, "/rrset") {
					fmt.Fprint(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<ResourceRecordSets><ResourceRecordSet><Name>app.example.com.</Name><Type>A</Type>
<AliasTarget><DNSName>example.us-east-1.elb.amazonaws.com.</DNSName><HostedZoneId>ZTARGET</HostedZoneId><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>
</ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>`)
					return
				}
				fmt.Fprint(w, `<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><CallerReference>test</CallerReference>
<Config><PrivateZone>true</PrivateZone></Config><ResourceRecordSetCount>1</ResourceRecordSetCount>
</HostedZone></HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>
</ListHostedZonesResponse>`)
			}))
			defer server.Close()
			client := route53.NewFromConfig(aws.Config{
				Region: tc.region, BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{},
			})
			zones, errs := listHostedZones(context.Background(), client, tc.region)
			require.Empty(t, errs)
			require.Len(t, zones, 1)
			require.Equal(t, "Z123", zones[0].Identification.Id)
			require.Equal(t, "arn:"+tc.partition+":route53:::hostedzone/Z123", zones[0].Identification.Arn)
			require.True(t, zones[0].Configuration.HostedZone.PrivateZone)
			require.Len(t, zones[0].Resources.RecordSets, 1)
			require.Equal(t, "app.example.com.", zones[0].Resources.RecordSets[0].Name)
			require.Equal(t, "ZTARGET", zones[0].Resources.RecordSets[0].AliasTarget.HostedZoneId)
		})
	}
}

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
	data, err := json.Marshal(resources)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.Len(t, fields, 1)
	assert.Contains(t, fields, "recordSets")
}

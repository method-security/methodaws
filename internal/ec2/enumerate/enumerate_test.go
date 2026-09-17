package enumerate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerationPreservesReservationOwnersAndValidInstances(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "DescribeInstances", r.Form.Get("Action"))
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprint(w, `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<reservationSet>
<item><instancesSet><item><instanceId>i-missing-owner</instanceId></item></instancesSet></item>
<item><ownerId>123456789012</ownerId><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId></item></instancesSet></item>
<item><ownerId>210987654321</ownerId><instancesSet><item><instanceId>i-0123456789abcdef1</instanceId></item></instancesSet></item>
</reservationSet></DescribeInstancesResponse>`)
	}))
	defer server.Close()
	instances, errs := enumerateEc2ForRegion(context.Background(), aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{},
	}, "us-east-1", make(instanceProfileCache))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "i-missing-owner")
	require.Len(t, instances, 2)
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", instances[0].Identification.Arn)
	assert.Equal(t, "arn:aws:ec2:us-east-1:210987654321:instance/i-0123456789abcdef1", instances[1].Identification.Arn)
}

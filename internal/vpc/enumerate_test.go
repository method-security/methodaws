package vpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	vpcfern "github.com/Method-Security/methodaws/generated/go/vpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertAWSSubnetPreservesPrivateDNSNameOptions(t *testing.T) {
	t.Parallel()

	subnet, errs := convertAWSSubnetToFern(types.Subnet{
		SubnetId: aws.String("subnet-0123456789abcdef0"),
		OwnerId:  aws.String("123456789012"),
		PrivateDnsNameOptionsOnLaunch: &types.PrivateDnsNameOptionsOnLaunch{
			HostnameType:                    types.HostnameTypeResourceName,
			EnableResourceNameDnsARecord:    aws.Bool(true),
			EnableResourceNameDnsAAAARecord: aws.Bool(false),
		},
	}, "us-east-1")

	require.Empty(t, errs)
	require.NotNil(t, subnet.Configuration.PrivateDnsNameOptionsOnLaunch)
	options := subnet.Configuration.PrivateDnsNameOptionsOnLaunch
	require.NotNil(t, options.HostnameType)
	assert.Equal(t, vpcfern.SubnetHostnameTypeResourceName, *options.HostnameType)
	assert.True(t, aws.ToBool(options.EnableResourceNameDnsARecord))
	assert.False(t, aws.ToBool(options.EnableResourceNameDnsAaaaRecord))
}

func TestVPCIdentityUsesReportedOwnerAndPartition(t *testing.T) {
	vpc, errs := convertAWSVPCToFern(types.Vpc{
		VpcId: aws.String("vpc-example"), OwnerId: aws.String("123456789012"),
	}, "us-gov-west-1")
	require.Empty(t, errs)
	require.NotNil(t, vpc)
	assert.Equal(t, "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:vpc/vpc-example", vpc.Identification.Arn)
	assert.Nil(t, vpc.Identification.Name)

	vpc, errs = convertAWSVPCToFern(types.Vpc{VpcId: aws.String("vpc-example")}, "us-east-1")
	assert.Nil(t, vpc)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0], "missing owner")
}

func TestSubnetIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		owner   *string
		arn     *string
		wantErr bool
	}{
		{name: "construct from owner", owner: aws.String("123456789012")},
		{name: "returned ARN", arn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-example")},
		{name: "missing owner and ARN", wantErr: true},
		{name: "invalid ARN", arn: aws.String("bad"), wantErr: true},
		{name: "blank ARN", owner: aws.String("123456789012"), arn: aws.String(""), wantErr: true},
		{name: "wrong owner", owner: aws.String("999999999999"), arn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-example"), wantErr: true},
		{name: "wrong region", arn: aws.String("arn:aws:ec2:us-west-2:123456789012:subnet/subnet-example"), wantErr: true},
		{name: "wrong partition", arn: aws.String("arn:aws-cn:ec2:us-east-1:123456789012:subnet/subnet-example"), wantErr: true},
		{name: "wrong ID", arn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-other"), wantErr: true},
		{name: "wrong service", arn: aws.String("arn:aws:rds:us-east-1:123456789012:subnet/subnet-example"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subnet, errs := convertAWSSubnetToFern(types.Subnet{
				SubnetId: aws.String("subnet-example"), OwnerId: tc.owner, SubnetArn: tc.arn,
			}, "us-east-1")
			if tc.wantErr {
				assert.Nil(t, subnet)
				require.NotEmpty(t, errs)
				return
			}
			require.Empty(t, errs)
			require.NotNil(t, subnet)
			assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-example", subnet.Identification.Arn)
		})
	}
}

func TestEnumerationSkipsUnresolvedParentsAndRetainsPriorPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "DescribeVpcs":
			if r.Form.Get("NextToken") != "" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied</Message></Error></Errors></Response>`)
				return
			}
			_, _ = fmt.Fprint(w, `<DescribeVpcsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<vpcSet><item><vpcId>vpc-valid</vpcId><ownerId>123456789012</ownerId></item>
<item><vpcId>vpc-missing-owner</vpcId></item></vpcSet><nextToken>page2</nextToken></DescribeVpcsResponse>`)
		case "DescribeSubnets":
			_, _ = fmt.Fprint(w, `<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<subnetSet><item><subnetId>subnet-valid</subnetId><vpcId>vpc-valid</vpcId><ownerId>123456789012</ownerId></item>
<item><subnetId>subnet-orphan</subnetId><vpcId>vpc-unresolved</vpcId><ownerId>123456789012</ownerId></item>
</subnetSet></DescribeSubnetsResponse>`)
		default:
			t.Errorf("unexpected action: %s", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	report := EnumerateVPC(context.Background(), aws.Config{
		BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{},
	}, vpcfern.VpcEnumerateConfig{AccountId: "999999999999", Regions: []string{"us-east-1"}})
	require.Len(t, report.Result.Vpcs, 1)
	vpc := report.Result.Vpcs[0]
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-valid", vpc.Identification.Arn)
	require.Len(t, vpc.Resources.Subnets, 1)
	assert.Equal(t, "subnet-valid", vpc.Resources.Subnets[0].Identification.Id)
	assert.Len(t, report.Errors, 3)
}

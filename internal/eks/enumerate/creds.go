package eks

import (
	"context"
	"encoding/base64"

	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func CredsEks(ctx context.Context, cfg aws.Config, clusterName string) (*eksfern.EksCredentialReport, error) {
	eksClient := eks.NewFromConfig(cfg)
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   "",
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}
	account := aws.ToString(accountID)

	clusterOutput, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}
	if clusterOutput.Cluster == nil || clusterOutput.Cluster.Arn == nil || clusterOutput.Cluster.Name == nil {
		errors = append(errors, "EKS cluster response is missing its ARN or name")
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{cfg.Region},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}

	gen, err := token.NewGenerator(true, false)
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}
	clusterID := aws.ToString(clusterOutput.Cluster.Id)
	if clusterID == "" {
		clusterID = aws.ToString(clusterOutput.Cluster.Name)
	}
	tok, err := gen.GetWithSTS(clusterID, awssts.NewFromConfig(cfg))
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}

	expiration := tok.Expiration
	var caCert string
	if clusterOutput.Cluster.CertificateAuthority != nil {
		caCert = aws.ToString(clusterOutput.Cluster.CertificateAuthority.Data)
	}
	encodedToken := base64.StdEncoding.EncodeToString([]byte(tok.Token))
	credInfo := eksfern.CredentialInfo{
		Url:        aws.ToString(clusterOutput.Cluster.Endpoint),
		Token:      encodedToken,
		CaCert:     &caCert,
		Expiration: &expiration,
		ClusterArn: *clusterOutput.Cluster.Arn,
		Region:     cfg.Region,
	}

	report := eksfern.EksCredentialReport{
		Config: &eksfern.EksCredentialConfig{
			AccountId:   aws.ToString(accountID),
			Regions:     []string{cfg.Region},
			ClusterName: clusterName,
		},
		Result: &eksfern.EksCredentialResult{
			Credential: &credInfo,
		},
		Errors: errors,
	}
	return &report, nil
}

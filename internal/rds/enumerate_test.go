package rds

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"
)

func TestConvertDBInstanceRequiresCompleteIdentity(t *testing.T) {
	instance, errs := convertAWSDBInstanceToFern(types.DBInstance{DBInstanceIdentifier: aws.String("database")}, "us-east-1")

	require.Nil(t, instance)
	require.Equal(t, []string{"RDS DB instance identifier, ARN, or region is missing"}, errs)
}

func TestConvertDBInstancePreservesConfiguredRoles(t *testing.T) {
	instance, errs := convertAWSDBInstanceToFern(types.DBInstance{
		DBInstanceIdentifier: aws.String("database"),
		DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:database"),
		MonitoringRoleArn:    aws.String("arn:aws:iam::123456789012:role/monitoring"),
		AssociatedRoles: []types.DBInstanceRole{
			{RoleArn: aws.String("arn:aws:iam::123456789012:role/integrations/import"), FeatureName: aws.String("s3Import"), Status: aws.String("INVALID")},
			{RoleArn: aws.String("not-an-arn")},
			{RoleArn: aws.String("arn:aws:iam::123456789012:role/export"), Status: aws.String("PENDING")},
		},
	}, "us-east-1")

	require.NotNil(t, instance)
	require.Len(t, errs, 1)
	require.Len(t, instance.Resources.IamRoles, 2)
	require.Equal(t, "import", *instance.Resources.IamRoles[0].RoleName)
	require.Equal(t, "s3Import", *instance.Resources.IamRoles[0].FeatureName)
	require.Equal(t, "INVALID", *instance.Resources.IamRoles[0].Status)
	require.Equal(t, "PENDING", *instance.Resources.IamRoles[1].Status)
	require.Equal(t, "arn:aws:iam::123456789012:role/monitoring", *instance.Configuration.Monitoring.MonitoringRoleArn)
}

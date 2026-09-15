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

// Package utils provides common utility functions used across the methodaws codebase.
package utils

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

// BuildRelatedARN builds an ARN using the partition and account from an authoritative source ARN.
func BuildRelatedARN(sourceARN, service, region, resource string) (string, error) {
	parsedARN, err := arn.Parse(sourceARN)
	if err != nil {
		return "", fmt.Errorf("parse source ARN: %w", err)
	}
	if parsedARN.Partition == "" || parsedARN.AccountID == "" {
		return "", fmt.Errorf("source ARN must include a partition and account ID")
	}

	return arn.ARN{
		Partition: parsedARN.Partition,
		Service:   service,
		Region:    region,
		AccountID: parsedARN.AccountID,
		Resource:  resource,
	}.String(), nil
}

// BuildRegionalARN builds an ARN using the AWS partition that owns region.
func BuildRegionalARN(region, service, accountID, resource string) (string, error) {
	partition, err := awsPartitionForRegion(region)
	if err != nil {
		return "", err
	}
	return arn.ARN{
		Partition: partition,
		Service:   service,
		Region:    region,
		AccountID: accountID,
		Resource:  resource,
	}.String(), nil
}

// BuildGlobalARNForRegion builds a global-resource ARN in the partition that owns region.
func BuildGlobalARNForRegion(region, service, accountID, resource string) (string, error) {
	partition, err := awsPartitionForRegion(region)
	if err != nil {
		return "", err
	}
	return arn.ARN{
		Partition: partition,
		Service:   service,
		AccountID: accountID,
		Resource:  resource,
	}.String(), nil
}

func awsPartitionForRegion(region string) (string, error) {
	partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !ok {
		return "", fmt.Errorf("no AWS partition found for region %q", region)
	}
	return partition.ID(), nil
}

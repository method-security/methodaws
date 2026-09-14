// Package utils provides common utility functions used across the methodaws codebase.
package utils

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
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

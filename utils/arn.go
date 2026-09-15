// Package utils provides common utility functions used across the methodaws codebase.
package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+$`)

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
	if !awsRegionPattern.MatchString(region) {
		return "", fmt.Errorf("invalid AWS region %q", region)
	}

	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn", nil
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov", nil
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b", nil
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso", nil
	case strings.HasPrefix(region, "eu-isoe-"):
		return "aws-iso-e", nil
	case strings.HasPrefix(region, "us-isof-"):
		return "aws-iso-f", nil
	case strings.HasPrefix(region, "eusc-"):
		return "aws-eusc", nil
	default:
		return "aws", nil
	}
}

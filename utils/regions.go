package utils

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/palantir/witchcraft-go-logging/wlog"

	// Import wlog-zap for its side effects, initializing the zap logger
	_ "github.com/palantir/witchcraft-go-logging/wlog-zap"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func GetAWSRegions(ctx context.Context, cfg aws.Config, selectedRegions []string) ([]string, error) {
	logger := svc1log.New(os.Stderr, wlog.InfoLevel)
	ctx = svc1log.WithLogger(ctx, logger)
	log := svc1log.FromContext(ctx)

	log.Info("Starting GetAWSRegions function")

	normalizedSelectedRegions := selectedRegions
	if len(selectedRegions) > 0 {
		regions, err := NormalizeSelectedRegions(selectedRegions)
		if err != nil {
			return nil, err
		}
		normalizedSelectedRegions = regions
	}

	queryRegion, err := regionDiscoveryQueryRegion(cfg.Region, normalizedSelectedRegions)
	if err != nil {
		return nil, err
	}
	queryConfig := cfg.Copy()
	queryConfig.Region = queryRegion
	regions, err := enabledAWSRegions(ctx, ec2.NewFromConfig(queryConfig), normalizedSelectedRegions)
	if err != nil {
		var discoveryErr *describeRegionsRequestError
		if !errors.As(err, &discoveryErr) {
			log.Error("Failed to validate enabled AWS regions", svc1log.SafeParam("region", queryRegion), svc1log.Stacktrace(err))
			return nil, err
		}
		fallbackRegions, fallbackErr := regionDiscoveryFallback(cfg.Region, normalizedSelectedRegions, err)
		if fallbackErr != nil {
			log.Error("Failed to discover enabled AWS regions", svc1log.SafeParam("region", queryRegion), svc1log.Stacktrace(err))
			return nil, fallbackErr
		}
		log.Warn(
			"Unable to validate enabled AWS regions; using configured regions",
			svc1log.SafeParam("regions", fallbackRegions),
			svc1log.Stacktrace(err),
		)
		if len(normalizedSelectedRegions) == 0 {
			return fallbackRegions, fmt.Errorf("AWS region coverage is incomplete; scanning only %s: %w", strings.Join(fallbackRegions, ", "), err)
		}
		return fallbackRegions, nil
	}

	log.Info("Discovered enabled AWS regions", svc1log.SafeParam("regions", regions))
	return regions, nil
}

func regionDiscoveryFallback(configRegion string, selectedRegions []string, discoveryErr error) ([]string, error) {
	if len(selectedRegions) > 0 {
		return selectedRegions, nil
	}
	if configRegion != "" {
		regions, err := NormalizeSelectedRegions([]string{configRegion})
		if err != nil {
			return nil, fmt.Errorf("describe enabled AWS regions: %w; configured region is invalid: %v", discoveryErr, err)
		}
		return regions, nil
	}
	return nil, discoveryErr
}

func regionDiscoveryQueryRegion(configRegion string, selectedRegions []string) (string, error) {
	if len(selectedRegions) == 0 {
		if configRegion != "" {
			return configRegion, nil
		}
		return "us-east-1", nil
	}

	partition, err := awsPartitionForRegion(selectedRegions[0])
	if err != nil {
		return "", err
	}
	switch partition {
	case "aws-cn":
		return "cn-north-1", nil
	case "aws-us-gov":
		return "us-gov-west-1", nil
	case "aws-iso":
		return "us-iso-east-1", nil
	case "aws-iso-b":
		return "us-isob-east-1", nil
	case "aws-iso-e":
		return "eu-isoe-west-1", nil
	case "aws-iso-f":
		return "us-isof-south-1", nil
	case "aws-eusc":
		return "eusc-de-east-1", nil
	default:
		return "us-east-1", nil
	}
}

type describeRegionsAPI interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

type describeRegionsRequestError struct {
	err error
}

func (e *describeRegionsRequestError) Error() string {
	return fmt.Sprintf("describe enabled AWS regions: %v", e.err)
}

func (e *describeRegionsRequestError) Unwrap() error {
	return e.err
}

func enabledAWSRegions(ctx context.Context, client describeRegionsAPI, selectedRegions []string) ([]string, error) {
	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, &describeRegionsRequestError{err: err}
	}
	if output == nil {
		return nil, fmt.Errorf("describe enabled AWS regions returned no response")
	}

	enabled := make(map[string]struct{}, len(output.Regions))
	for _, region := range output.Regions {
		if region.RegionName != nil && *region.RegionName != "" {
			enabled[*region.RegionName] = struct{}{}
		}
	}

	if len(enabled) == 0 {
		return nil, fmt.Errorf("no enabled AWS regions returned")
	}
	if len(selectedRegions) > 0 {
		var unavailable []string
		for _, region := range selectedRegions {
			if _, ok := enabled[region]; !ok {
				unavailable = append(unavailable, region)
			}
		}
		if len(unavailable) > 0 {
			return nil, fmt.Errorf("AWS regions are not enabled or do not exist: %s", strings.Join(unavailable, ", "))
		}
		return selectedRegions, nil
	}
	return sortedRegionNames(enabled), nil
}

// NormalizeSelectedRegions validates region syntax and partition, and removes duplicates without AWS API calls.
func NormalizeSelectedRegions(selectedRegions []string) ([]string, error) {
	selected := make(map[string]struct{}, len(selectedRegions))
	partition := ""
	for _, region := range selectedRegions {
		if region == "" {
			continue
		}
		regionPartition, err := awsPartitionForRegion(region)
		if err != nil {
			return nil, err
		}
		if partition != "" && regionPartition != partition {
			return nil, fmt.Errorf("selected AWS regions must belong to one partition")
		}
		partition = regionPartition
		selected[region] = struct{}{}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("at least one AWS region must be selected")
	}
	return sortedRegionNames(selected), nil
}

func sortedRegionNames(regions map[string]struct{}) []string {
	result := make([]string, 0, len(regions))
	for region := range regions {
		result = append(result, region)
	}
	sort.Strings(result)
	return result
}

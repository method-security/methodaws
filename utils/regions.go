package utils

import (
	// Standard
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go/aws/endpoints"
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

	queryRegion, err := regionDiscoveryQueryRegion(cfg.Region, selectedRegions)
	if err != nil {
		return nil, err
	}

	queryConfig := cfg.Copy()
	queryConfig.Region = queryRegion
	regions, err := enabledAWSRegions(ctx, ec2.NewFromConfig(queryConfig), selectedRegions)
	if err != nil {
		log.Error("Failed to discover enabled AWS regions", svc1log.SafeParam("region", queryRegion), svc1log.Stacktrace(err))
		return nil, err
	}

	log.Info("Discovered enabled AWS regions", svc1log.SafeParam("regions", regions))
	return regions, nil
}

func regionDiscoveryQueryRegion(configRegion string, selectedRegions []string) (string, error) {
	for _, region := range selectedRegions {
		if region == "" {
			continue
		}
		partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
		if !ok {
			return "", fmt.Errorf("no AWS partition found for region %q", region)
		}
		for _, selectedRegion := range selectedRegions {
			if selectedRegion == "" {
				continue
			}
			selectedPartition, selected := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), selectedRegion)
			if !selected || selectedPartition.ID() != partition.ID() {
				return "", fmt.Errorf("selected AWS regions must belong to one partition")
			}
		}
		return region, nil
	}
	if configRegion != "" {
		return configRegion, nil
	}
	return "us-east-1", nil
}

type describeRegionsAPI interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

func enabledAWSRegions(ctx context.Context, client describeRegionsAPI, selectedRegions []string) ([]string, error) {
	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, fmt.Errorf("describe enabled AWS regions: %w", err)
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

	if len(selectedRegions) == 0 {
		if len(enabled) == 0 {
			return nil, fmt.Errorf("no enabled AWS regions returned")
		}
		return sortedRegionNames(enabled), nil
	}

	selected := make(map[string]struct{}, len(selectedRegions))
	for _, region := range selectedRegions {
		if region != "" {
			selected[region] = struct{}{}
		}
	}

	valid := make(map[string]struct{}, len(selected))
	var invalid []string
	for region := range selected {
		if _, ok := enabled[region]; ok {
			valid[region] = struct{}{}
		} else {
			invalid = append(invalid, region)
		}
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return nil, fmt.Errorf("AWS regions are not enabled or do not exist: %s", strings.Join(invalid, ", "))
	}

	return sortedRegionNames(valid), nil
}

func sortedRegionNames(regions map[string]struct{}) []string {
	result := make([]string, 0, len(regions))
	for region := range regions {
		result = append(result, region)
	}
	sort.Strings(result)
	return result
}

func GetRegionsToCheck(ctx context.Context, selectedRegions []string) []string {
	log := svc1log.FromContext(ctx)
	if len(selectedRegions) > 0 {
		log.Info(fmt.Sprintf("Using selected regions: %v", selectedRegions))
		return selectedRegions
	}

	log.Info("No regions selected, checking all regions")
	allRegions := make(map[string]struct{})
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()

	for _, p := range partitions {
		for region := range p.Regions() {
			allRegions[region] = struct{}{}
		}
	}
	regions := sortedRegionNames(allRegions)
	log.Info(fmt.Sprintf("All regions to check: %v", regions))
	return regions
}

// GetGeneralRegionsList returns a list of known AWS regions.
func GetGeneralRegionsList() []string {
	resolver := endpoints.DefaultResolver()
	for _, partition := range resolver.(endpoints.EnumPartitions).Partitions() {
		if partition.ID() != endpoints.AwsPartitionID {
			continue
		}
		regions := make(map[string]struct{}, len(partition.Regions()))
		for region := range partition.Regions() {
			regions[region] = struct{}{}
		}
		return sortedRegionNames(regions)
	}
	return nil
}

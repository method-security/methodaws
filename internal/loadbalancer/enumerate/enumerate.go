package loadbalancer

import (
	"context"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateLoadBalancers enumerates load balancers based on the provided configuration
func EnumerateLoadBalancers(ctx context.Context, awsConfig aws.Config, config loadbalancerfern.LoadBalancerEnumerateConfig) *loadbalancerfern.LoadBalancerEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Load Balancer enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("versionsCount", len(config.Versions)))

	// Initialize report
	report := &loadbalancerfern.LoadBalancerEnumerateReport{
		Result: &loadbalancerfern.LoadBalancerEnumerateResult{},
		Config: &config,
	}

	var allLoadBalancers []*loadbalancerfern.LoadBalancerInstance
	var allErrors []string

	// Process each version requested
	if config.Versions != nil {
		for _, version := range config.Versions {
			switch version {
			case loadbalancerfern.LoadBalancerVersionV1:
				log.Info("Processing v1 load balancers")
				v1LBs, errors := enumerateV1LoadBalancersAllRegions(ctx, awsConfig, config.Regions, config.AccountId)
				allLoadBalancers = append(allLoadBalancers, v1LBs...)
				allErrors = append(allErrors, errors...)

			case loadbalancerfern.LoadBalancerVersionV2:
				log.Info("Processing v2 load balancers")
				v2LBs, errors := enumerateV2LoadBalancersAllRegions(ctx, awsConfig, config.Regions)
				allLoadBalancers = append(allLoadBalancers, v2LBs...)
				allErrors = append(allErrors, errors...)
			}
		}
	}

	// Marshal report
	if len(allLoadBalancers) > 0 {
		report.Result.LoadBalancers = allLoadBalancers
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed Load Balancer enumeration",
		svc1log.SafeParam("totalLoadBalancers", len(allLoadBalancers)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

package loadbalancer

import (
	"context"
	"fmt"
	"strings"

	"github.com/Method-Security/methodaws/generated/go/common"
	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	methodawsutils "github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1LoadBalancersAllRegions enumerates v1 load balancers across all specified regions
func enumerateV1LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string, accountID string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancerInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v1 load balancers in region", svc1log.SafeParam("region", region))
		loadBalancers, errors := enumerateV1LoadBalancersForRegion(ctx, awsConfig, region, accountID)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v1 load balancers in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allLoadBalancers = append(allLoadBalancers, loadBalancers...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v1 load balancers in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("loadBalancerCount", len(loadBalancers)))
	}

	return allLoadBalancers, allErrors
}

// enumerateV1LoadBalancersForRegion enumerates v1 load balancers for a specific region
func enumerateV1LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region, accountID string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancerInstance
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to list v1 load balancers in region %s: %s", region, err.Error())
			log.Error("Error listing v1 load balancers", svc1log.SafeParam("error", err.Error()), svc1log.SafeParam("region", region))
			errorMessages = append(errorMessages, errorMsg)
			break
		}

		for _, lb := range page.LoadBalancerDescriptions {
			if lb.LoadBalancerName == nil {
				log.Warn("LoadBalancer name is nil for load balancer", svc1log.SafeParam("loadBalancer", lb))
				errorMessages = append(errorMessages, "LoadBalancer name is nil")
				continue
			}

			identification, err := classicLoadBalancerIdentification(lb, region, accountID)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			// Create configuration info
			configuration := &loadbalancerfern.LoadBalancerConfigurationInfo{
				LoadBalancerType: loadbalancerfern.LoadBalancerTypeClassic,
				DnsName:          lb.DNSName,
				CreatedTime:      lb.CreatedTime,
				HostedZoneId:     lb.CanonicalHostedZoneNameID,
			}

			// Get targets and listeners
			targets, errors := targetsForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			listeners, errors := listenersForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			// Create resource info
			resources := &loadbalancerfern.LoadBalancerResourceInfo{
				Listeners: listeners,
				Targets:   targets,
			}

			// Add resource references with deduplication
			if lb.VPCId != nil {
				resources.Vpc = &common.VpcReference{
					Id:        aws.ToString(lb.VPCId),
					Region:    region,
					SubnetIds: lb.Subnets,
				}
			}
			resources.SecurityGroups = createSecurityGroupReferences(lb.SecurityGroups, region)

			// Create LoadBalancerInstance
			loadBalancer := &loadbalancerfern.LoadBalancerInstance{
				Identification: identification,
				Configuration:  configuration,
				Resources:      resources,
			}

			loadBalancers = append(loadBalancers, loadBalancer)
		}
	}

	return loadBalancers, errorMessages
}

func classicLoadBalancerIdentification(
	loadBalancer types.LoadBalancerDescription,
	region string,
	accountID string,
) (*loadbalancerfern.LoadBalancerIdentificationInfo, error) {
	identification := &loadbalancerfern.LoadBalancerIdentificationInfo{
		Name:   loadBalancer.LoadBalancerName,
		Region: region,
	}
	if loadBalancer.LoadBalancerName == nil {
		return identification, fmt.Errorf("Classic load balancer name is nil")
	}

	loadBalancerARN, err := methodawsutils.BuildRegionalARN(
		region,
		"elasticloadbalancing",
		accountID,
		"loadbalancer/"+*loadBalancer.LoadBalancerName,
	)
	if err != nil {
		return identification, fmt.Errorf("build Classic load balancer ARN for %s: %w", *loadBalancer.LoadBalancerName, err)
	}
	identification.Arn = &loadBalancerARN
	return identification, nil
}

func targetsForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*loadbalancerfern.Target, []string) {
	targets := []*loadbalancerfern.Target{}
	errorMessages := []string{}
	var instancePort *int
	ports := make(map[int]struct{})
	for _, description := range loadBalancer.ListenerDescriptions {
		if description.Listener != nil && description.Listener.InstancePort != nil {
			ports[int(*description.Listener.InstancePort)] = struct{}{}
		}
	}
	if len(ports) == 1 {
		for port := range ports {
			portValue := port
			instancePort = &portValue
		}
	}

	for _, instance := range loadBalancer.Instances {
		if instance.InstanceId == nil {
			errorMessages = append(errorMessages, "Classic load balancer instance ID is nil")
			continue
		}
		targetType := loadbalancerfern.TargetTypeInstance
		target := &loadbalancerfern.Target{
			Id:   *instance.InstanceId,
			Port: instancePort,
			Type: &targetType,
		}
		targets = append(targets, target)
	}

	return targets, errorMessages
}

func listenersForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*loadbalancerfern.Listener, []string) {
	listeners := []*loadbalancerfern.Listener{}
	errorMessages := []string{}

	for _, listener := range loadBalancer.ListenerDescriptions {
		if listener.Listener == nil {
			errorMessages = append(errorMessages, "Classic load balancer listener is nil")
			continue
		}
		port := int(listener.Listener.LoadBalancerPort)
		fernListener := &loadbalancerfern.Listener{Port: &port}

		// Convert protocol
		if listener.Listener.Protocol != nil {
			if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(*listener.Listener.Protocol)); err == nil {
				fernListener.Protocol = &protocol
			} else {
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert listener protocol for load balancer %s: %s", aws.ToString(loadBalancer.LoadBalancerName), err.Error()))
			}
		}

		listeners = append(listeners, fernListener)
	}
	return listeners, errorMessages
}

// createSecurityGroupReferences creates security group references from AWS security groups
func createSecurityGroupReferences(sgIDs []string, region string) []*common.SecurityGroupReference {
	var securityGroups []*common.SecurityGroupReference
	for _, sgID := range sgIDs {
		if sgID != "" {
			securityGroups = append(securityGroups, &common.SecurityGroupReference{
				Id:     sgID,
				Region: region,
			})
		}
	}
	return securityGroups
}

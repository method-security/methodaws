package loadbalancer

import (
	"context"
	"fmt"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// convertAWSLoadBalancerType converts AWS LoadBalancerTypeEnum to Fern LoadBalancerType
func convertAWSLoadBalancerType(awsType types.LoadBalancerTypeEnum) (loadbalancerfern.LoadBalancerType, error) {
	switch strings.ToUpper(string(awsType)) {
	case "APPLICATION":
		return loadbalancerfern.LoadBalancerTypeApplication, nil
	case "NETWORK":
		return loadbalancerfern.LoadBalancerTypeNetwork, nil
	case "GATEWAY":
		return loadbalancerfern.LoadBalancerTypeGateway, nil
	default:
		return "", fmt.Errorf("unsupported load balancer type: %s", awsType)
	}
}

// enumerateV2LoadBalancersAllRegions enumerates v2 load balancers across all specified regions
func enumerateV2LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancerInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v2 load balancers in region", svc1log.SafeParam("region", region))
		loadBalancers, errors := enumerateV2LoadBalancersForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v2 load balancers in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allLoadBalancers = append(allLoadBalancers, loadBalancers...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v2 load balancers in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("loadBalancerCount", len(loadBalancers)))
	}

	return allLoadBalancers, allErrors
}

// enumerateV2LoadBalancersForRegion enumerates v2 load balancers for a specific region
func enumerateV2LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancingv2.NewFromConfig(cfg)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancerInstance
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to list v2 load balancers in region %s: %s", region, err.Error())
			log.Error("Error listing v2 load balancers", svc1log.SafeParam("error", err.Error()), svc1log.SafeParam("region", region))
			errorMessages = append(errorMessages, errorMsg)
			break
		}

		for _, lb := range page.LoadBalancers {
			if lb.LoadBalancerArn == nil {
				log.Warn("LoadBalancer name is nil for load balancer", svc1log.SafeParam("loadBalancer", lb))
				errorMessages = append(errorMessages, "LoadBalancer name is nil")
				continue
			}

			// Create identification info
			identification := &loadbalancerfern.LoadBalancerIdentificationInfo{
				Arn:    lb.LoadBalancerArn,
				Name:   lb.LoadBalancerName,
				Region: region,
			}

			// Create configuration info
			configuration := &loadbalancerfern.LoadBalancerConfigurationInfo{
				DnsName:      lb.DNSName,
				CreatedTime:  lb.CreatedTime,
				HostedZoneId: lb.CanonicalHostedZoneId,
			}

			// Convert LoadBalancerType from AWS SDK
			if lbType, err := convertAWSLoadBalancerType(lb.Type); err == nil {
				configuration.LoadBalancerType = lbType
			} else {
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer type for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
			}

			// Convert IP address type
			if lb.IpAddressType != "" {
				if ipType, err := loadbalancerfern.NewIpAddressTypeFromString(strings.ToUpper(string(lb.IpAddressType))); err == nil {
					configuration.IpAddressType = &ipType
				} else {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert IP address type for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
				}
			}

			// Convert state
			if lb.State != nil {
				if state, err := loadbalancerfern.NewLoadBalancerStateFromString(strings.ToUpper(string(lb.State.Code))); err == nil {
					configuration.State = &state
				} else {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer state for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
				}
			}

			// Get listeners and target groups
			listeners, errors := listenersForLoadBalancerV2(ctx, client, lb.LoadBalancerArn)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			targetGroups, errors := targetGroupForLoadBalancerV2(ctx, client, lb.LoadBalancerArn, region)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			// Create resource info with deduplicated references
			resources := &loadbalancerfern.LoadBalancerResourceInfo{
				Listeners:    listeners,
				TargetGroups: targetGroups,
			}

			// Add resource references with deduplication
			if lb.VpcId != nil {
				resources.Vpc = createVpcReferenceFromLB(lb, region)
			}
			resources.SecurityGroups = createSecurityGroupReferencesFromLB(lb.SecurityGroups, region)

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

type elbv2ResourceAPI interface {
	DescribeListeners(context.Context, *elasticloadbalancingv2.DescribeListenersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
	DescribeListenerCertificates(context.Context, *elasticloadbalancingv2.DescribeListenerCertificatesInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenerCertificatesOutput, error)
	DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elasticloadbalancingv2.DescribeTargetHealthInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error)
}

func listenersForLoadBalancerV2(ctx context.Context, client elbv2ResourceAPI, loadBalancerArn *string) ([]*loadbalancerfern.Listener, []string) {
	log := svc1log.FromContext(ctx)

	listeners := []*loadbalancerfern.Listener{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeListenersPaginator(client, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: loadBalancerArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return listeners, errorMessages
		}

		for _, listener := range page.Listeners {
			if listener.ListenerArn == nil {
				errorMessages = append(errorMessages, "Listener ARN is nil")
				log.Warn("Listener ARN is nil for listener", svc1log.SafeParam("listener", listener))
				continue
			}
			var port *int
			if listener.Port != nil {
				portValue := int(*listener.Port)
				port = &portValue
			}
			var certificates []*loadbalancerfern.Certificate
			if len(listener.Certificates) > 0 {
				var errs []string
				certificates, errs = certificatesForListenerV2(ctx, client, listener.ListenerArn)
				if len(errs) > 0 {
					errorMessages = append(errorMessages, errs...)
				}
			}
			fernListener := &loadbalancerfern.Listener{
				Arn:          *listener.ListenerArn,
				Port:         port,
				Certificates: certificates,
			}

			// Convert protocol
			if listener.Protocol != "" {
				if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(string(listener.Protocol))); err == nil {
					fernListener.Protocol = &protocol
				} else {
					errorMessages = append(errorMessages, "Failed to convert listener protocol: "+err.Error())
				}
			}

			listeners = append(listeners, fernListener)
		}
	}
	return listeners, errorMessages
}

func targetGroupForLoadBalancerV2(ctx context.Context, client elbv2ResourceAPI, loadBalancerArn *string, region string) ([]*loadbalancerfern.TargetGroupInstance, []string) {
	log := svc1log.FromContext(ctx)
	targetGroups := []*loadbalancerfern.TargetGroupInstance{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: loadBalancerArn,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return targetGroups, errorMessages
		}

		for _, awsTargetGroup := range page.TargetGroups {
			if awsTargetGroup.TargetGroupArn == nil {
				log.Warn("Target group ARN is nil for target group", svc1log.SafeParam("targetGroup", awsTargetGroup))
				errorMessages = append(errorMessages, "Target group ARN is nil")
				continue
			}

			// Create identification info
			identification := &loadbalancerfern.TargetGroupIdentificationInfo{
				Arn:    aws.ToString(awsTargetGroup.TargetGroupArn),
				Name:   awsTargetGroup.TargetGroupName,
				Region: region,
			}

			// Create configuration info
			configuration := &loadbalancerfern.TargetGroupConfigurationInfo{}

			// Set port if available
			if awsTargetGroup.Port != nil {
				portValue := int(*awsTargetGroup.Port)
				configuration.Port = &portValue
			}

			// Convert IP address type
			if awsTargetGroup.IpAddressType != "" {
				if ipType, err := loadbalancerfern.NewTargetGroupIpAddressTypeFromString(strings.ToUpper(string(awsTargetGroup.IpAddressType))); err == nil {
					configuration.IpAddressType = &ipType
				} else {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert target group IP address type '%s': %s", awsTargetGroup.IpAddressType, err.Error()))
				}
			}

			// Convert protocol
			if awsTargetGroup.Protocol != "" {
				if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(string(awsTargetGroup.Protocol))); err == nil {
					configuration.Protocol = &protocol
				} else {
					errorMessages = append(errorMessages, "Failed to convert target group protocol: "+err.Error())
				}
			}

			// Get targets
			targets, err := targetsForTargetGroupV2(ctx, client, awsTargetGroup)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}

			// Create TargetGroupInstance
			targetGroup := &loadbalancerfern.TargetGroupInstance{
				Identification: identification,
				Configuration:  configuration,
			}

			// Only create resource info if there are targets
			if len(targets) > 0 {
				resources := &loadbalancerfern.TargetGroupResourceInfo{
					Targets: targets,
				}
				targetGroup.Resources = resources
			}

			targetGroups = append(targetGroups, targetGroup)
		}
	}
	return targetGroups, errorMessages
}

// targetsForTargetGroupV2 converts AWS TargetGroup to Fern Target
func targetsForTargetGroupV2(ctx context.Context, client elbv2ResourceAPI, targetGroup types.TargetGroup) ([]*loadbalancerfern.Target, error) {
	var targets []*loadbalancerfern.Target
	output, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: targetGroup.TargetGroupArn,
	})
	if err != nil {
		return targets, err
	}
	if output == nil {
		return targets, fmt.Errorf("DescribeTargetHealth returned no response")
	}

	// Convert target type once for all targets in this group
	var targetType loadbalancerfern.TargetType
	if tt, err := loadbalancerfern.NewTargetTypeFromString(strings.ToUpper(string(targetGroup.TargetType))); err == nil {
		targetType = tt
	} else {
		return targets, fmt.Errorf("failed to convert target type: %w", err)
	}
	for _, targetHealth := range output.TargetHealthDescriptions {
		if targetHealth.Target == nil || targetHealth.Target.Id == nil {
			continue
		}
		var availabilityZone *string = nil
		if targetHealth.Target.AvailabilityZone != nil {
			availabilityZone = targetHealth.Target.AvailabilityZone
		}
		target := &loadbalancerfern.Target{
			Id:               aws.ToString(targetHealth.Target.Id),
			Type:             &targetType,
			AvailabilityZone: availabilityZone,
		}
		if targetHealth.Target.Port != nil {
			portValue := int(*targetHealth.Target.Port)
			target.Port = &portValue
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func certificatesForListenerV2(ctx context.Context, client elbv2ResourceAPI, listenerARN *string) ([]*loadbalancerfern.Certificate, []string) {
	certs := []*loadbalancerfern.Certificate{}
	var errors []string
	paginator := elasticloadbalancingv2.NewDescribeListenerCertificatesPaginator(
		client,
		&elasticloadbalancingv2.DescribeListenerCertificatesInput{ListenerArn: listenerARN},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return certs, append(errors, err.Error())
		}
		for _, cert := range page.Certificates {
			if cert.CertificateArn == nil {
				continue
			}
			certs = append(certs, &loadbalancerfern.Certificate{
				Arn:       *cert.CertificateArn,
				IsDefault: aws.ToBool(cert.IsDefault),
			})
		}
	}
	return certs, errors
}

// Resource discovery helper functions with deduplication
func createVpcReferenceFromLB(lb types.LoadBalancer, region string) *common.VpcReference {
	if lb.VpcId == nil {
		return nil
	}

	var subnetIds []string
	for _, az := range lb.AvailabilityZones {
		if az.SubnetId != nil {
			subnetIds = append(subnetIds, *az.SubnetId)
		}
	}

	return &common.VpcReference{
		Id:        *lb.VpcId,
		Region:    region,
		SubnetIds: subnetIds,
	}
}

func createSecurityGroupReferencesFromLB(sgIDs []string, region string) []*common.SecurityGroupReference {
	sgMap := make(map[string]*common.SecurityGroupReference)

	for _, sgID := range sgIDs {
		if sgID != "" {
			key := sgID
			if _, exists := sgMap[key]; !exists {
				sgMap[key] = &common.SecurityGroupReference{
					Id:     sgID,
					Region: region,
				}
			}
		}
	}

	var securityGroups []*common.SecurityGroupReference
	for _, sg := range sgMap {
		securityGroups = append(securityGroups, sg)
	}
	return securityGroups
}

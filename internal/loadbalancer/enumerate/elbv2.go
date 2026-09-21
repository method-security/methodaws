package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
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
			if aws.ToString(lb.LoadBalancerArn) == "" || region == "" {
				log.Warn("Load balancer ARN or region is empty", svc1log.SafeParam("loadBalancer", lb))
				errorMessages = append(errorMessages, fmt.Sprintf("Load balancer %q in region %q has no required ARN or region", aws.ToString(lb.LoadBalancerName), region))
				continue
			}

			// Create identification info
			identification := &loadbalancerfern.LoadBalancerIdentificationInfo{
				Arn:    *lb.LoadBalancerArn,
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
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer type for %s in region %s: %s", *lb.LoadBalancerArn, region, err.Error()))
				continue
			}

			if lb.Scheme != "" {
				if scheme, err := loadbalancerfern.NewLoadBalancerSchemeFromString(strings.ToUpper(strings.ReplaceAll(string(lb.Scheme), "-", "_"))); err == nil {
					configuration.Scheme = &scheme
				} else {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer scheme for %s in region %s: %s", *lb.LoadBalancerArn, region, err.Error()))
				}
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
			for _, err := range errors {
				errorMessages = append(errorMessages, fmt.Sprintf("Load balancer %s in region %s: %s", *lb.LoadBalancerArn, region, err))
			}

			targetGroups, errors := targetGroupForLoadBalancerV2(ctx, client, lb.LoadBalancerArn, region)
			for _, err := range errors {
				errorMessages = append(errorMessages, fmt.Sprintf("Load balancer %s in region %s: %s", *lb.LoadBalancerArn, region, err))
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
			if aws.ToString(listener.ListenerArn) == "" {
				errorMessages = append(errorMessages, "Listener ARN is empty")
				log.Warn("Listener ARN is empty for listener", svc1log.SafeParam("listener", listener))
				continue
			}
			var port *int
			if listener.Port != nil {
				portValue := int(*listener.Port)
				port = &portValue
			}
			certificates, certificateErrors := certificatesFromListener(listener.Certificates)
			for _, err := range certificateErrors {
				errorMessages = append(errorMessages, fmt.Sprintf("Listener %s: %s", *listener.ListenerArn, err))
			}
			if len(listener.Certificates) > 0 {
				var errs []string
				discoveredCertificates, errs := certificatesForListenerV2(ctx, client, listener.ListenerArn)
				certificates = mergeCertificates(certificates, discoveredCertificates)
				if len(errs) > 0 {
					errorMessages = append(errorMessages, errs...)
				}
			}
			fernListener := &loadbalancerfern.Listener{
				Id:           *listener.ListenerArn,
				Arn:          listener.ListenerArn,
				Port:         port,
				Certificates: certificates,
			}
			forwardTargets, forwardErrors := defaultForwardTargetGroups(listener.DefaultActions)
			fernListener.DefaultForwardTargetGroups = forwardTargets
			for _, err := range forwardErrors {
				errorMessages = append(errorMessages, fmt.Sprintf("Listener %s: %s", *listener.ListenerArn, err))
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

func defaultForwardTargetGroups(actions []types.Action) ([]*loadbalancerfern.ForwardTargetGroup, []string) {
	var targets []*loadbalancerfern.ForwardTargetGroup
	var errs []string
	for _, action := range actions {
		if action.Type != types.ActionTypeEnumForward {
			continue
		}
		groups := []types.TargetGroupTuple{{TargetGroupArn: action.TargetGroupArn}}
		if action.ForwardConfig != nil && len(action.ForwardConfig.TargetGroups) > 0 {
			groups = action.ForwardConfig.TargetGroups
		}
		for _, group := range groups {
			groupARN := aws.ToString(group.TargetGroupArn)
			parsed, err := arn.Parse(groupARN)
			if err != nil || parsed.Service != "elasticloadbalancing" || parsed.Region == "" ||
				parsed.AccountID == "" || !strings.HasPrefix(parsed.Resource, "targetgroup/") ||
				strings.TrimPrefix(parsed.Resource, "targetgroup/") == "" {
				errs = append(errs, fmt.Sprintf("Default forward action has an invalid target group ARN %q", groupARN))
				continue
			}
			target := &loadbalancerfern.ForwardTargetGroup{Arn: groupARN}
			if group.Weight != nil {
				weight := int(*group.Weight)
				if weight < 0 || weight > 999 {
					errs = append(errs, fmt.Sprintf("Default forward target group %s has invalid weight %d", groupARN, weight))
				} else {
					target.Weight = &weight
				}
			}
			targets = append(targets, target)
		}
	}
	return targets, errs
}

func certificatesFromListener(certificates []types.Certificate) ([]*loadbalancerfern.Certificate, []string) {
	result := make([]*loadbalancerfern.Certificate, 0, len(certificates))
	var errs []string
	for _, certificate := range certificates {
		if aws.ToString(certificate.CertificateArn) == "" {
			errs = append(errs, "Default certificate is missing its ARN")
			continue
		}
		result = append(result, &loadbalancerfern.Certificate{
			Arn: *certificate.CertificateArn,
			// DescribeListeners returns the default certificate but omits IsDefault.
			IsDefault: true,
		})
	}
	return result, errs
}

func mergeCertificates(certificateGroups ...[]*loadbalancerfern.Certificate) []*loadbalancerfern.Certificate {
	var result []*loadbalancerfern.Certificate
	byARN := make(map[string]*loadbalancerfern.Certificate)
	for _, certificates := range certificateGroups {
		for _, certificate := range certificates {
			if certificate == nil {
				continue
			}
			if existing, ok := byARN[certificate.Arn]; ok {
				existing.IsDefault = existing.IsDefault || certificate.IsDefault
				continue
			}
			byARN[certificate.Arn] = certificate
			result = append(result, certificate)
		}
	}
	return result
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
			if aws.ToString(awsTargetGroup.TargetGroupArn) == "" {
				log.Warn("Target group ARN is empty for target group", svc1log.SafeParam("targetGroup", awsTargetGroup))
				errorMessages = append(errorMessages, "Target group ARN is empty")
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
				errorMessages = append(errorMessages, fmt.Sprintf("Target group %s: %s", *awsTargetGroup.TargetGroupArn, err))
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
	if len(output.TargetHealthDescriptions) == 0 {
		return targets, nil
	}

	// Convert target type once for all targets in this group
	var targetType loadbalancerfern.TargetType
	if tt, err := loadbalancerfern.NewTargetTypeFromString(strings.ToUpper(string(targetGroup.TargetType))); err == nil {
		targetType = tt
	} else {
		return targets, fmt.Errorf("failed to convert target type: %w", err)
	}
	var errs []error
	for _, targetHealth := range output.TargetHealthDescriptions {
		if targetHealth.Target == nil || aws.ToString(targetHealth.Target.Id) == "" {
			errs = append(errs, fmt.Errorf("target group %s has a target without an ID", aws.ToString(targetGroup.TargetGroupArn)))
			continue
		}
		var availabilityZone *string = nil
		if targetHealth.Target.AvailabilityZone != nil {
			availabilityZone = targetHealth.Target.AvailabilityZone
		}
		target := &loadbalancerfern.Target{
			Id:               aws.ToString(targetHealth.Target.Id),
			Type:             targetType,
			AvailabilityZone: availabilityZone,
		}
		if targetHealth.Target.Port != nil {
			portValue := int(*targetHealth.Target.Port)
			target.Port = &portValue
		}
		targets = append(targets, target)
	}
	return targets, errors.Join(errs...)
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
			return certs, append(errors, fmt.Sprintf("Listener %s certificates: %s", aws.ToString(listenerARN), err))
		}
		for _, cert := range page.Certificates {
			if aws.ToString(cert.CertificateArn) == "" {
				errors = append(errors, fmt.Sprintf("Listener %s has a certificate without an ARN", aws.ToString(listenerARN)))
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
	if aws.ToString(lb.VpcId) == "" {
		return nil
	}

	var subnetIds []string
	for _, az := range lb.AvailabilityZones {
		if aws.ToString(az.SubnetId) != "" {
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

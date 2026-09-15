// Package route53 provides logic and data structures necessary to enumerate and integrate AWS Route 53 resources.
package route53

import (
	// Standard
	"context"
	"fmt"
	"strings"

	// Generated
	route53fern "github.com/Method-Security/methodaws/generated/go/route53"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// REGION is the fallback when no region is configured for the global service.
const (
	REGION = "us-east-1"
)

func listHostedZones(ctx context.Context, route53Client *route53.Client) ([]route53fern.EnrichedHostedZone, []string) {
	log := svc1log.FromContext(ctx)
	var zones []route53fern.EnrichedHostedZone
	var errors []string

	log.Info("Starting Route53 hosted zones enumeration")
	paginator := route53.NewListHostedZonesPaginator(route53Client, &route53.ListHostedZonesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Failed to get next page of hosted zones", svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Failed to get next page of hosted zones: %s", err.Error()))
			break
		}

		log.Info("Retrieved hosted zones page", svc1log.SafeParam("zoneCount", len(page.HostedZones)))

		for _, hostedZone := range page.HostedZones {
			zoneID := canonicalHostedZoneID(aws.ToString(hostedZone.Id))
			if zoneID == "" || aws.ToString(hostedZone.Name) == "" {
				errors = append(errors, fmt.Sprintf("Route53 hosted zone %q (%q) has an incomplete identity", aws.ToString(hostedZone.Name), aws.ToString(hostedZone.Id)))
				continue
			}
			// Prepare identification info
			identification := &route53fern.HostedZoneIdentificationInfo{
				Id:   zoneID,
				Name: *hostedZone.Name,
			}

			// Prepare configuration info
			configuration := &route53fern.HostedZoneConfigurationInfo{}
			if aws.ToString(hostedZone.CallerReference) != "" {
				configuration.CallerReference = hostedZone.CallerReference
			}

			// Add optional hosted zone config if it exists
			if hostedZone.Config != nil {
				if hostedZone.Config.Comment != nil {
					hostedZoneConfig := &route53fern.HostedZone{
						Comment:     hostedZone.Config.Comment,
						PrivateZone: hostedZone.Config.PrivateZone,
					}
					configuration.HostedZone = hostedZoneConfig
				} else {
					hostedZoneConfig := &route53fern.HostedZone{
						PrivateZone: hostedZone.Config.PrivateZone,
					}
					configuration.HostedZone = hostedZoneConfig
				}
			}

			// Add resource record set count if it exists
			if hostedZone.ResourceRecordSetCount != nil {
				recordCount := int(*hostedZone.ResourceRecordSetCount)
				configuration.ResourceRecordSetCount = &recordCount
			}

			// Add linked service if it exists
			if hostedZone.LinkedService != nil {
				linkedService := &route53fern.LinkedService{
					ServicePrincipal: hostedZone.LinkedService.ServicePrincipal,
					Description:      hostedZone.LinkedService.Description,
				}
				configuration.LinkedService = linkedService
			}

			// Create the enriched hosted zone with nested structure
			zone := route53fern.EnrichedHostedZone{
				Identification: identification,
				Configuration:  configuration,
			}

			log.Info("Processing hosted zone", svc1log.SafeParam("zoneName", identification.Name), svc1log.SafeParam("zoneId", identification.Id))

			resourceRecordSets, dnsErrors := listDNSRecords(ctx, route53Client, identification.Id)
			if len(dnsErrors) > 0 {
				log.Warn("Errors getting DNS records for hosted zone",
					svc1log.SafeParam("zoneName", identification.Name),
					svc1log.SafeParam("zoneId", identification.Id))
				errors = append(errors, dnsErrors...)
			}

			// Add resources if there are record sets
			if len(resourceRecordSets) > 0 {
				zone.Resources = resourceInfoForRecordSets(resourceRecordSets)
			}

			zones = append(zones, zone)

			log.Info("Successfully processed hosted zone",
				svc1log.SafeParam("zoneName", identification.Name),
				svc1log.SafeParam("recordCount", len(resourceRecordSets)))
		}
	}

	log.Info("Completed Route53 hosted zones enumeration", svc1log.SafeParam("totalZones", len(zones)))
	return zones, errors
}

func listDNSRecords(ctx context.Context, route53Client *route53.Client, zoneID string) ([]*route53fern.ResourceRecordSet, []string) {
	log := svc1log.FromContext(ctx)
	var recordSets []*route53fern.ResourceRecordSet
	var errors []string

	log.Info("Retrieving DNS records for zone", svc1log.SafeParam("zoneId", zoneID))

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}

	paginator := route53.NewListResourceRecordSetsPaginator(route53Client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Failed to get next page of DNS records",
				svc1log.SafeParam("zoneId", zoneID),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Failed to get DNS records for zone %s: %s", zoneID, err.Error()))
			break
		}

		log.Info("Retrieved DNS records page",
			svc1log.SafeParam("zoneId", zoneID),
			svc1log.SafeParam("recordCount", len(page.ResourceRecordSets)))

		for _, recordSet := range page.ResourceRecordSets {
			if aws.ToString(recordSet.Name) == "" {
				errors = append(errors, fmt.Sprintf("DNS record name is missing in zone %s", zoneID))
				continue
			}
			recordType, err := route53fern.NewRecordTypeFromString(string(recordSet.Type))
			if err != nil {
				errors = append(errors, fmt.Sprintf("DNS record %q in zone %s has an invalid type %q: %s", *recordSet.Name, zoneID, recordSet.Type, err))
				continue
			}
			nonSimpleRouting := recordSet.Weight != nil || recordSet.Region != "" || recordSet.Failover != "" ||
				recordSet.GeoLocation != nil || recordSet.GeoProximityLocation != nil || recordSet.CidrRoutingConfig != nil || aws.ToBool(recordSet.MultiValueAnswer)
			if (nonSimpleRouting || recordSet.SetIdentifier != nil) && aws.ToString(recordSet.SetIdentifier) == "" {
				errors = append(errors, fmt.Sprintf("DNS record %q (%s) in zone %s is missing its routing set identifier", *recordSet.Name, recordType, zoneID))
				continue
			}
			// Convert AWS SDK ResourceRecordSet to fern ResourceRecordSet
			fernRecord := &route53fern.ResourceRecordSet{
				Name: *recordSet.Name,
				Type: recordType,
			}

			// Handle optional fields
			if recordSet.AliasTarget != nil {
				targetZoneID := canonicalHostedZoneID(aws.ToString(recordSet.AliasTarget.HostedZoneId))
				if aws.ToString(recordSet.AliasTarget.DNSName) == "" || targetZoneID == "" {
					errors = append(errors, fmt.Sprintf("DNS record %q (%s) in zone %s has an alias target without a DNS name or hosted-zone ID", *recordSet.Name, recordType, zoneID))
				} else {
					fernRecord.AliasTarget = &route53fern.AliasTarget{
						DnsName:              *recordSet.AliasTarget.DNSName,
						HostedZoneId:         targetZoneID,
						EvaluateTargetHealth: recordSet.AliasTarget.EvaluateTargetHealth,
					}
				}
			}

			if recordSet.CidrRoutingConfig != nil {
				if aws.ToString(recordSet.CidrRoutingConfig.CollectionId) == "" || aws.ToString(recordSet.CidrRoutingConfig.LocationName) == "" {
					errors = append(errors, fmt.Sprintf("DNS record %q (%s) in zone %s has incomplete CIDR routing identity", *recordSet.Name, recordType, zoneID))
				} else {
					fernRecord.CidrRouting = &route53fern.CidrRouting{
						CollectionId: *recordSet.CidrRoutingConfig.CollectionId,
						LocationName: *recordSet.CidrRoutingConfig.LocationName,
					}
				}
			}

			if recordSet.Failover != "" {
				failover := string(recordSet.Failover)
				fernRecord.Failover = &failover
			}

			if recordSet.GeoLocation != nil {
				geoLocation := &route53fern.GeoLocation{
					ContinentCode:   recordSet.GeoLocation.ContinentCode,
					CountryCode:     recordSet.GeoLocation.CountryCode,
					SubdivisionCode: recordSet.GeoLocation.SubdivisionCode,
				}
				fernRecord.GeoLocation = geoLocation
			}

			if recordSet.HealthCheckId != nil {
				if *recordSet.HealthCheckId != "" {
					fernRecord.HealthCheckId = recordSet.HealthCheckId
				} else {
					errors = append(errors, fmt.Sprintf("DNS record %q (%s) in zone %s has an empty health-check ID", *recordSet.Name, recordType, zoneID))
				}
			}

			if recordSet.MultiValueAnswer != nil {
				fernRecord.MultiValueAnswer = recordSet.MultiValueAnswer
			}

			if recordSet.Region != "" {
				region := string(recordSet.Region)
				fernRecord.Region = &region
			}

			if recordSet.ResourceRecords != nil {
				var resourceRecords []*route53fern.ResourceRecord
				for _, rr := range recordSet.ResourceRecords {
					if aws.ToString(rr.Value) == "" {
						errors = append(errors, fmt.Sprintf("DNS record %q (%s) in zone %s has a resource record without a value", *recordSet.Name, recordType, zoneID))
						continue
					}
					resourceRecord := &route53fern.ResourceRecord{
						Value: *rr.Value,
					}
					resourceRecords = append(resourceRecords, resourceRecord)
				}
				fernRecord.ResourceRecords = resourceRecords
			}

			if recordSet.SetIdentifier != nil {
				fernRecord.SetIdentifier = recordSet.SetIdentifier
			}

			if recordSet.TTL != nil {
				ttl := int(*recordSet.TTL)
				fernRecord.Ttl = &ttl
			}

			if recordSet.Weight != nil {
				weight := int(*recordSet.Weight)
				fernRecord.Weight = &weight
			}

			recordSets = append(recordSets, fernRecord)
		}
	}

	log.Info("Completed DNS records retrieval",
		svc1log.SafeParam("zoneId", zoneID),
		svc1log.SafeParam("totalRecords", len(recordSets)))

	return recordSets, errors
}

// EnumerateRoute53 retrieves all Route 53 hosted zones available to the caller and returns a Route53EnumerateReport struct
func EnumerateRoute53(ctx context.Context, awscfg aws.Config, config route53fern.Route53EnumerateConfig) *route53fern.Route53EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Route53 enumeration")

	// Let the SDK select the global endpoint and signing region for the configured partition.
	if awscfg.Region == "" {
		awscfg.Region = REGION
	}

	// Initialize Report
	report := route53fern.Route53EnumerateReport{
		Result: &route53fern.Route53Result{},
		Config: &config,
	}
	var errors []string

	// Create a new AWS config for this region
	route53Client := route53.NewFromConfig(awscfg)

	// List hosted zones
	hostedZones, zoneErrors := listHostedZones(ctx, route53Client)
	if len(zoneErrors) > 0 {
		log.Warn("Errors occurred while listing hosted zones",
			svc1log.SafeParam("region", awscfg.Region),
			svc1log.SafeParam("errorCount", len(zoneErrors)))
		errors = append(errors, zoneErrors...)
	}

	// Add hosted zones to report
	result := route53fern.Route53Result{}
	if len(hostedZones) > 0 {
		// Convert to slice of pointers
		var hostedZonePointers []*route53fern.EnrichedHostedZone
		for i := range hostedZones {
			hostedZonePointers = append(hostedZonePointers, &hostedZones[i])
		}
		result.HostedZones = hostedZonePointers
	}

	// Only add hosted zones if there are any
	if len(result.HostedZones) > 0 {
		report.Result.HostedZones = result.HostedZones
	}
	report.Errors = errors
	return &report
}

func resourceInfoForRecordSets(records []*route53fern.ResourceRecordSet) *route53fern.HostedZoneResourceInfo {
	// DNS targets identify endpoints, but do not expose authoritative AWS resource ARNs.
	return &route53fern.HostedZoneResourceInfo{
		RecordSets: records,
	}
}

func canonicalHostedZoneID(id string) string {
	id = strings.TrimPrefix(id, "/hostedzone/")
	if id == "" || strings.ContainsAny(id, "/ \t\r\n") {
		return ""
	}
	return id
}

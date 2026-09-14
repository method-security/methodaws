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

// REGION is the region to use for Route53 enumeration.
// Route53 is a global service, so we only need to query once.
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
			if hostedZone.CallerReference == nil || hostedZone.Id == nil || hostedZone.Name == nil {
				errors = append(errors, "Route53 hosted zone identity is incomplete")
				continue
			}
			// Prepare identification info
			identification := &route53fern.HostedZoneIdentificationInfo{
				CallerReference: *hostedZone.CallerReference,
				Id:              *hostedZone.Id,
				Name:            *hostedZone.Name,
			}

			// Prepare configuration info
			configuration := &route53fern.HostedZoneConfigurationInfo{}

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
			if recordSet.Name == nil {
				errors = append(errors, fmt.Sprintf("DNS record name is missing in zone %s", zoneID))
				continue
			}
			// Convert AWS SDK ResourceRecordSet to fern ResourceRecordSet
			fernRecord := &route53fern.ResourceRecordSet{
				Name: *recordSet.Name,
				Type: route53fern.RecordType(strings.ToUpper(string(recordSet.Type))),
			}

			// Handle optional fields
			if recordSet.AliasTarget != nil && recordSet.AliasTarget.DNSName != nil && recordSet.AliasTarget.HostedZoneId != nil {
				aliasTarget := &route53fern.AliasTarget{
					DnsName:              *recordSet.AliasTarget.DNSName,
					HostedZoneId:         *recordSet.AliasTarget.HostedZoneId,
					EvaluateTargetHealth: recordSet.AliasTarget.EvaluateTargetHealth,
				}
				fernRecord.AliasTarget = aliasTarget
			}

			if recordSet.CidrRoutingConfig != nil && recordSet.CidrRoutingConfig.CollectionId != nil &&
				recordSet.CidrRoutingConfig.LocationName != nil {
				cidrRouting := &route53fern.CidrRouting{
					CollectionId: *recordSet.CidrRoutingConfig.CollectionId,
					LocationName: *recordSet.CidrRoutingConfig.LocationName,
				}
				fernRecord.CidrRouting = cidrRouting
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
				fernRecord.HealthCheckId = recordSet.HealthCheckId
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
					if rr.Value == nil {
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

	// Set the region to us-east-1 for since Route53 is a global resounce and ignore the region data
	awscfg.Region = REGION

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

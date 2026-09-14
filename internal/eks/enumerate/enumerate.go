package eks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	"github.com/Method-Security/methodaws/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	eksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

// EnumerateEks enumerates EKS clusters based on the provided configuration
func EnumerateEks(ctx context.Context, awsConfig aws.Config, config eksfern.EksEnumerateConfig) *eksfern.EksEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting EKS enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &eksfern.EksEnumerateReport{
		Result: &eksfern.EksEnumerateResult{
			EksClusters: []*eksfern.EksInstance{},
		},
		Config: &config,
	}

	var allClusters []*eksfern.EksInstance
	var allErrors []string

	// Process each region
	for _, region := range config.Regions {
		log.Info("Processing EKS clusters in region", svc1log.SafeParam("region", region))
		clusters, errors := enumerateEksForRegion(ctx, awsConfig, region)
		allClusters = append(allClusters, clusters...)
		allErrors = append(allErrors, errors...)
	}

	// Populate report
	if len(allClusters) > 0 {
		report.Result.EksClusters = allClusters
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed EKS enumeration",
		svc1log.SafeParam("totalClusters", len(allClusters)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// enumerateEksForRegion enumerates all EKS clusters in a specified region
func enumerateEksForRegion(ctx context.Context, cfg aws.Config, region string) ([]*eksfern.EksInstance, []string) {
	cfg.Region = region

	eksSvc := eks.NewFromConfig(cfg)
	var clusters []*eksfern.EksInstance
	var errors []string

	// List clusters with pagination
	var allClusterNames []string
	var nextToken *string
	for {
		clusterList, err := eksSvc.ListClusters(ctx, &eks.ListClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error listing clusters in region %s: %s", region, err.Error()))
			break
		}
		allClusterNames = append(allClusterNames, clusterList.Clusters...)
		if clusterList.NextToken == nil {
			break
		}
		nextToken = clusterList.NextToken
	}

	// Process each cluster
	for _, clusterName := range allClusterNames {
		cluster, errs := processCluster(ctx, cfg, eksSvc, clusterName, region)
		if cluster != nil {
			clusters = append(clusters, cluster)
		}
		errors = append(errors, errs...)
	}

	return clusters, errors
}

// processCluster processes a single EKS cluster and its node groups
func processCluster(ctx context.Context, cfg aws.Config, eksSvc *eks.Client, clusterName string, region string) (*eksfern.EksInstance, []string) {
	var errors []string
	log := svc1log.FromContext(ctx)

	// Describe cluster
	clusterDetail, err := eksSvc.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing cluster %s: %s", clusterName, err.Error()))
		return nil, errors
	}

	// Convert cluster to Fern format
	if clusterDetail.Cluster == nil {
		log.Warn("Cluster is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster is nil")
		return nil, errors
	}
	if clusterDetail.Cluster.Name == nil {
		log.Warn("Cluster name is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster name is nil")
		return nil, errors
	}
	if clusterDetail.Cluster.Arn == nil {
		log.Warn("Cluster ARN is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster ARN is nil")
		return nil, errors
	}

	// Convert cluster to Fern format with new structure
	cluster := convertClusterToFern(clusterDetail.Cluster, region)

	// Enumerate Kubernetes resources (nodes with nested pods, external services) if cluster is active
	if clusterDetail.Cluster.Status == eksTypes.ClusterStatusActive && clusterDetail.Cluster.Endpoint != nil {
		nodes, services, k8sErrors := enumerateKubernetesResources(ctx, cfg, clusterDetail.Cluster, region)
		errors = append(errors, k8sErrors...)

		if cluster.Resources == nil {
			cluster.Resources = &eksfern.EksResourceInfo{}
		}

		if len(nodes) > 0 {
			cluster.Resources.Nodes = nodes
		}
		if len(services) > 0 {
			cluster.Resources.Services = services
		}
	}

	return cluster, errors
}

// enumerateKubernetesResources enumerates nodes and external services from an active EKS cluster (pods are nested under nodes)
func enumerateKubernetesResources(ctx context.Context, cfg aws.Config, cluster *eksTypes.Cluster, region string) ([]*eksfern.KubernetesNode, []*eksfern.KubernetesService, []string) {
	var fernNodes []*eksfern.KubernetesNode
	var fernServices []*eksfern.KubernetesService
	var errors []string

	log := svc1log.FromContext(ctx)

	if cluster.Name == nil || cluster.Endpoint == nil {
		errors = append(errors, "Cluster name or endpoint is nil")
		return fernNodes, fernServices, errors
	}

	log.Info("Enumerating Kubernetes resources for cluster", svc1log.SafeParam("clusterName", *cluster.Name))

	// Create Kubernetes client
	kubeClient, err := createKubernetesClient(ctx, cfg, cluster)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to create Kubernetes client for cluster %s: %s", *cluster.Name, err.Error()))
		return fernNodes, fernServices, errors
	}

	// Get raw Kubernetes resources - collect what we can, don't discard on partial failure
	podList, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list pods in cluster %s: %s", *cluster.Name, err.Error()))
		podList = &v1.PodList{}
	}

	nodeList, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list nodes in cluster %s: %s", *cluster.Name, err.Error()))
		nodeList = &v1.NodeList{}
	}

	serviceList, err := kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list services in cluster %s: %s", *cluster.Name, err.Error()))
		serviceList = &v1.ServiceList{}
	}

	// Build service-pod relationships
	servicePodMap, podServiceMap := buildServicePodRelationships(serviceList.Items, podList.Items, region)

	// Convert all pods to Fern structures
	podMap := make(map[string]*eksfern.KubernetesPod)
	for _, pod := range podList.Items {
		fernPod := convertPodToFern(&pod, region)
		if fernPod != nil {
			// Add service relationships (deduplicated)
			if services, exists := podServiceMap[getPodKey(&pod)]; exists && len(services) > 0 {
				fernPod.Resources.Services = deduplicateStrings(services)
			}
			podMap[getPodKey(&pod)] = fernPod
		}
	}

	// Build node-pod relationships with full pod structures
	nodePodMap := buildNodePodStructures(nodeList.Items, podList.Items, podMap)

	// Convert nodes with full pod structures nested under them
	for _, node := range nodeList.Items {
		fernNode := convertNodeToFern(&node, region)
		if fernNode != nil {
			// Add full pod structures
			if pods, exists := nodePodMap[node.Name]; exists && len(pods) > 0 {
				fernNode.Resources.Pods = pods
			}
			fernNodes = append(fernNodes, fernNode)
		}
	}

	// Convert services (focus on external access) with pod relationships
	for _, service := range serviceList.Items {
		// Only capture services with external access (LoadBalancer, NodePort, or external IPs)
		if service.Spec.Type == v1.ServiceTypeLoadBalancer ||
			service.Spec.Type == v1.ServiceTypeNodePort ||
			len(service.Spec.ExternalIPs) > 0 {
			fernService := convertServiceToFern(&service, region)
			if fernService != nil {
				// Add pod relationships to resources section (resources is guaranteed to exist from convertServiceToFern)
				if podIds, exists := servicePodMap[getServiceKey(&service)]; exists && len(podIds) > 0 {
					fernService.Resources.TargetPods = podIds
				}
				fernServices = append(fernServices, fernService)
			}
		}
	}

	log.Info("Successfully enumerated Kubernetes resources with relationships",
		svc1log.SafeParam("clusterName", *cluster.Name),
		svc1log.SafeParam("nodeCount", len(fernNodes)),
		svc1log.SafeParam("serviceCount", len(fernServices)))

	return fernNodes, fernServices, errors
}

// createKubernetesClient creates a Kubernetes client for the EKS cluster
func createKubernetesClient(ctx context.Context, cfg aws.Config, cluster *eksTypes.Cluster) (*kubernetes.Clientset, error) {
	// Create token generator for AWS IAM authentication
	tokenGenerator, err := token.NewGenerator(true, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create token generator: %w", err)
	}

	// Generate token
	tok, err := tokenGenerator.GetWithOptions(ctx, &token.GetTokenOptions{
		ClusterID: *cluster.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Decode the certificate authority data
	if cluster.CertificateAuthority == nil || cluster.CertificateAuthority.Data == nil {
		return nil, fmt.Errorf("cluster %s has no certificate authority data", *cluster.Name)
	}
	caCert, err := base64.StdEncoding.DecodeString(*cluster.CertificateAuthority.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate authority data: %w", err)
	}

	// Create Kubernetes config
	config := &rest.Config{
		Host:        *cluster.Endpoint,
		BearerToken: tok.Token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caCert,
		},
	}

	// Create Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return clientset, nil
}

// buildNodePodStructures builds relationships between nodes and their full pod structures
func buildNodePodStructures(nodes []v1.Node, pods []v1.Pod, podMap map[string]*eksfern.KubernetesPod) map[string][]*eksfern.KubernetesPod {
	// nodePodMap: node name -> list of full pod structures
	nodePodMap := make(map[string][]*eksfern.KubernetesPod)

	for _, pod := range pods {
		if pod.Spec.NodeName != "" {
			podKey := getPodKey(&pod)
			if fernPod, exists := podMap[podKey]; exists {
				nodePodMap[pod.Spec.NodeName] = append(nodePodMap[pod.Spec.NodeName], fernPod)
			}
		}
	}

	return nodePodMap
}

// deduplicateStrings removes duplicate strings from a slice while preserving order
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// resolveHostnameToIPs performs DNS lookup to get IP addresses for a hostname
func resolveHostnameToIPs(hostname string) []string {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return deduplicateStrings(ipStrings)
}

// isIPAddress checks if a string is an IP address (IPv4 or IPv6)
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// buildServicePodRelationships builds bidirectional relationships between services and pods
func buildServicePodRelationships(services []v1.Service, pods []v1.Pod, region string) (map[string][]*eksfern.KubernetesPodIdentificationInfo, map[string][]string) {
	// servicePodMap: service key -> list of pod identification info
	servicePodMap := make(map[string][]*eksfern.KubernetesPodIdentificationInfo)
	// podServiceMap: pod key -> list of service names
	podServiceMap := make(map[string][]string)

	for _, service := range services {
		serviceKey := getServiceKey(&service)
		var targetPodIds []*eksfern.KubernetesPodIdentificationInfo

		// Check if service has a selector
		if len(service.Spec.Selector) > 0 {
			for _, pod := range pods {
				// Check if pod matches service selector
				if podMatchesServiceSelector(&pod, service.Spec.Selector) {
					podKey := getPodKey(&pod)
					serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)

					// Create pod identification info
					podID := &eksfern.KubernetesPodIdentificationInfo{
						Name:      pod.Name,
						Namespace: pod.Namespace,
						Region:    region,
					}
					if pod.UID != "" {
						uid := string(pod.UID)
						podID.Uid = &uid
					}

					// Add to service -> pods mapping
					targetPodIds = append(targetPodIds, podID)

					// Add to pod -> services mapping
					if _, exists := podServiceMap[podKey]; !exists {
						podServiceMap[podKey] = []string{}
					}
					podServiceMap[podKey] = append(podServiceMap[podKey], serviceName)
				}
			}
		}

		if len(targetPodIds) > 0 {
			servicePodMap[serviceKey] = targetPodIds
		}
	}

	return servicePodMap, podServiceMap
}

// getServiceKey returns a unique key for a service
func getServiceKey(service *v1.Service) string {
	return fmt.Sprintf("%s/%s", service.Namespace, service.Name)
}

// getPodKey returns a unique key for a pod
func getPodKey(pod *v1.Pod) string {
	return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
}

// podMatchesServiceSelector checks if a pod matches a service selector
func podMatchesServiceSelector(pod *v1.Pod, selector map[string]string) bool {
	if pod.Labels == nil {
		return len(selector) == 0
	}

	// All selector labels must match pod labels
	for key, value := range selector {
		if podLabel, exists := pod.Labels[key]; !exists || podLabel != value {
			return false
		}
	}

	return true
}

// convertPodToFern converts a Kubernetes Pod to Fern format (simplified)
func convertPodToFern(pod *v1.Pod, region string) *eksfern.KubernetesPod {
	if pod == nil {
		return nil
	}

	// Create identification
	identification := &eksfern.KubernetesPodIdentificationInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Region:    region,
	}

	if pod.UID != "" {
		uid := string(pod.UID)
		identification.Uid = &uid
	}

	// Create configuration
	configuration := &eksfern.KubernetesPodConfigurationInfo{}

	if podStatus := convertPodStatusToEnum(pod.Status.Phase); podStatus != nil {
		configuration.Status = podStatus
	}

	if pod.Spec.NodeName != "" {
		configuration.NodeName = &pod.Spec.NodeName
	}

	if !pod.CreationTimestamp.IsZero() {
		configuration.CreatedAt = &pod.CreationTimestamp.Time
	}

	if pod.Labels != nil {
		configuration.Labels = pod.Labels
	}

	if pod.Annotations != nil {
		configuration.Annotations = pod.Annotations
	}

	// Simplify containers to just names
	if len(pod.Spec.Containers) > 0 {
		var containerNames []string
		for _, container := range pod.Spec.Containers {
			containerNames = append(containerNames, container.Name)
		}
		configuration.Containers = deduplicateStrings(containerNames)
	}

	// Create resources section
	resources := &eksfern.KubernetesPodResourceInfo{}

	// Extract IP addresses from pod status
	var ipAddresses []string
	var fqdns []string

	// Add primary pod IP
	if pod.Status.PodIP != "" {
		ipAddresses = append(ipAddresses, pod.Status.PodIP)
	}

	// Add additional IPs (for dual-stack networking)
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" && podIP.IP != pod.Status.PodIP {
			ipAddresses = append(ipAddresses, podIP.IP)
		}
	}

	// Extract FQDN from hostname and subdomain if available
	if pod.Spec.Hostname != "" {
		hostname := pod.Spec.Hostname
		if pod.Spec.Subdomain != "" {
			hostname = fmt.Sprintf("%s.%s", pod.Spec.Hostname, pod.Spec.Subdomain)
		}
		fqdns = append(fqdns, hostname)
	}

	// Set IP addresses and FQDNs if we found any (deduplicated)
	if len(ipAddresses) > 0 {
		resources.IpAddresses = deduplicateStrings(ipAddresses)
	}
	if len(fqdns) > 0 {
		resources.Fqdns = deduplicateStrings(fqdns)
	}

	return &eksfern.KubernetesPod{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}
}

// convertNodeToFern converts a Kubernetes Node to Fern format (simplified)
func convertNodeToFern(node *v1.Node, region string) *eksfern.KubernetesNode {
	if node == nil {
		return nil
	}

	// Create identification
	identification := &eksfern.KubernetesNodeIdentificationInfo{
		Name:   node.Name,
		Region: region,
	}

	if node.UID != "" {
		uid := string(node.UID)
		identification.Uid = &uid
	}

	// Create configuration
	configuration := &eksfern.KubernetesNodeConfigurationInfo{}

	if !node.CreationTimestamp.IsZero() {
		configuration.CreatedAt = &node.CreationTimestamp.Time
	}

	if node.Labels != nil {
		configuration.Labels = node.Labels
	}

	if node.Annotations != nil {
		configuration.Annotations = node.Annotations
	}

	// Simplify capacity to string map
	if node.Status.Capacity != nil {
		capacity := make(map[string]string)
		for k, v := range node.Status.Capacity {
			capacity[string(k)] = v.String()
		}
		configuration.Capacity = capacity
	}

	// Simplify allocatable to string map
	if node.Status.Allocatable != nil {
		allocatable := make(map[string]string)
		for k, v := range node.Status.Allocatable {
			allocatable[string(k)] = v.String()
		}
		configuration.Allocatable = allocatable
	}

	// Simplify conditions to string list
	if len(node.Status.Conditions) > 0 {
		var conditions []string
		for _, condition := range node.Status.Conditions {
			conditions = append(conditions, fmt.Sprintf("%s:%s", condition.Type, condition.Status))
		}
		configuration.Conditions = deduplicateStrings(conditions)
	}

	// Create resources section with parsed addresses
	resources := &eksfern.KubernetesNodeResourceInfo{}

	// Parse addresses into IP addresses and FQDNs
	if len(node.Status.Addresses) > 0 {
		var ipAddresses []string
		var fqdns []string

		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case v1.NodeInternalIP, v1.NodeExternalIP:
				ipAddresses = append(ipAddresses, addr.Address)
			case v1.NodeInternalDNS, v1.NodeExternalDNS, v1.NodeHostName:
				fqdns = append(fqdns, addr.Address)
			}
		}

		if len(ipAddresses) > 0 {
			resources.IpAddresses = deduplicateStrings(ipAddresses)
		}
		if len(fqdns) > 0 {
			resources.Fqdns = deduplicateStrings(fqdns)
		}
	}

	return &eksfern.KubernetesNode{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}
}

// convertServiceToFern converts a Kubernetes Service to Fern format (simplified for external access)
func convertServiceToFern(service *v1.Service, region string) *eksfern.KubernetesService {
	if service == nil {
		return nil
	}

	// Create identification
	identification := &eksfern.KubernetesServiceIdentificationInfo{
		Name:      service.Name,
		Namespace: service.Namespace,
		Region:    region,
	}

	if service.UID != "" {
		uid := string(service.UID)
		identification.Uid = &uid
	}

	// Create configuration
	configuration := &eksfern.KubernetesServiceConfigurationInfo{}

	// Service type belongs in configuration
	if serviceType := convertServiceTypeToEnum(service.Spec.Type); serviceType != nil {
		configuration.ServiceType = serviceType
	}

	if !service.CreationTimestamp.IsZero() {
		configuration.CreatedAt = &service.CreationTimestamp.Time
	}

	if service.Labels != nil {
		configuration.Labels = service.Labels
	}

	if service.Annotations != nil {
		configuration.Annotations = service.Annotations
	}

	if service.Spec.Selector != nil {
		configuration.Selector = service.Spec.Selector
	}

	// Create resources section with exposure information
	resources := &eksfern.KubernetesServiceResourceInfo{}

	// Cluster IP address
	if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
		resources.ClusterIpAddress = &service.Spec.ClusterIP
	}

	// External IP addresses and endpoints
	if len(service.Spec.ExternalIPs) > 0 {
		// Set external IP addresses array
		resources.ExternalIpAddresses = deduplicateStrings(service.Spec.ExternalIPs)

		// Create external endpoints
		var externalEndpoints []*eksfern.ServiceEndpoint
		ports := getServicePorts(service)

		for _, ip := range service.Spec.ExternalIPs {
			endpoint := &eksfern.ServiceEndpoint{
				IpAddress: &ip,
				Ports:     ports,
			}
			externalEndpoints = append(externalEndpoints, endpoint)
		}
		resources.ExternalEndpoints = externalEndpoints
	}

	// Load balancer endpoints
	if len(service.Status.LoadBalancer.Ingress) > 0 {
		var lbEndpoints []*eksfern.ServiceEndpoint
		ports := getServicePorts(service)

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				// Create endpoint
				endpoint := &eksfern.ServiceEndpoint{
					IpAddress: &ingress.IP,
					Ports:     ports,
				}
				lbEndpoints = append(lbEndpoints, endpoint)
			}
			if ingress.Hostname != "" {
				endpoint := &eksfern.ServiceEndpoint{
					Hostname: &ingress.Hostname,
					Ports:    ports,
				}

				// Resolve hostname to IP addresses only if it's actually a hostname (not an IP)
				if !isIPAddress(ingress.Hostname) {
					if resolvedIPs := resolveHostnameToIPs(ingress.Hostname); len(resolvedIPs) > 0 {
						endpoint.ResolvedIpAddresses = resolvedIPs
					}
				}

				lbEndpoints = append(lbEndpoints, endpoint)
			}
		}

		resources.LoadBalancerEndpoints = lbEndpoints
	}

	return &eksfern.KubernetesService{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}
}

// getServicePorts extracts port information from a Kubernetes service as structured objects
func getServicePorts(service *v1.Service) []*eksfern.ServicePort {
	if len(service.Spec.Ports) == 0 {
		return nil
	}

	var ports []*eksfern.ServicePort
	for _, port := range service.Spec.Ports {
		servicePort := &eksfern.ServicePort{
			Port:     int(port.Port),
			Protocol: string(port.Protocol),
		}
		if port.NodePort > 0 {
			nodePort := int(port.NodePort)
			servicePort.NodePort = &nodePort
		}
		ports = append(ports, servicePort)
	}
	return ports
}

// convertServiceTypeToEnum converts Kubernetes service type to Fern enum
func convertServiceTypeToEnum(serviceType v1.ServiceType) *eksfern.ServiceType {
	switch serviceType {
	case v1.ServiceTypeClusterIP:
		return eksfern.ServiceTypeClusterIp.Ptr()
	case v1.ServiceTypeNodePort:
		return eksfern.ServiceTypeNodePort.Ptr()
	case v1.ServiceTypeLoadBalancer:
		return eksfern.ServiceTypeLoadBalancer.Ptr()
	case v1.ServiceTypeExternalName:
		return eksfern.ServiceTypeExternalName.Ptr()
	default:
		return nil
	}
}

// convertPodStatusToEnum converts Kubernetes pod phase to Fern enum
func convertPodStatusToEnum(phase v1.PodPhase) *eksfern.PodStatus {
	switch phase {
	case v1.PodPending:
		return eksfern.PodStatusPending.Ptr()
	case v1.PodRunning:
		return eksfern.PodStatusRunning.Ptr()
	case v1.PodSucceeded:
		return eksfern.PodStatusSucceeded.Ptr()
	case v1.PodFailed:
		return eksfern.PodStatusFailed.Ptr()
	case v1.PodUnknown:
		return eksfern.PodStatusUnknown.Ptr()
	default:
		return eksfern.PodStatusUnknown.Ptr()
	}
}

// convertClusterToFern converts AWS EKS cluster to Fern format with new structure
func convertClusterToFern(cluster *eksTypes.Cluster, region string) *eksfern.EksInstance {
	if cluster == nil || cluster.Arn == nil || cluster.Name == nil {
		return nil
	}

	// Create identification info
	identification := &eksfern.EksIdentificationInfo{
		Arn:    *cluster.Arn,
		Name:   *cluster.Name,
		Id:     cluster.Id,
		Region: region,
	}

	// Create configuration info
	configuration := &eksfern.EksConfigurationInfo{
		Status:          eksfern.ClusterStatus(string(cluster.Status)),
		Endpoint:        cluster.Endpoint,
		Version:         cluster.Version,
		PlatformVersion: cluster.PlatformVersion,
		CreatedAt:       cluster.CreatedAt,
		RoleArn:         cluster.RoleArn,
	}

	// Add service role reference
	if cluster.RoleArn != nil {
		configuration.ServiceRole = createIamRoleReference(*cluster.RoleArn, region)
	}

	// Add tags to configuration
	if cluster.Tags != nil {
		configuration.Tags = cluster.Tags
	}

	// Add access config to configuration
	if cluster.AccessConfig != nil {
		configuration.AccessConfig = convertAccessConfigToFern(cluster.AccessConfig)
	}

	// Create resource info (only include supported fields)
	resources := &eksfern.EksResourceInfo{}

	// Note: The following fields are not currently supported in EksResourceInfo:
	// - NodeGroups, ResourcesVpcConfig, KubernetesNetworkConfig, Logging, Identity,
	//   EncryptionConfig, ConnectorConfig, Health, OutpostConfig

	// Discover and add AWS resource references
	discoverEksResourceReferences(cluster, nil, resources, region)

	// Create EksInstance
	fernCluster := &eksfern.EksInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return fernCluster
}

func convertAccessConfigToFern(config *eksTypes.AccessConfigResponse) *eksfern.EksAccessConfig {
	if config == nil {
		return nil
	}

	return &eksfern.EksAccessConfig{
		AuthenticationMode:                      (*string)(&config.AuthenticationMode),
		BootstrapClusterCreatorAdminPermissions: config.BootstrapClusterCreatorAdminPermissions,
	}
}

// AWS Resource Reference Helper Functions

// createIamRoleReference creates an IAM role reference from an ARN
func createIamRoleReference(arn, region string) *common.IamRoleReference {
	if arn == "" {
		return nil
	}

	// Extract role name from ARN
	parts := strings.Split(arn, "/")
	var roleName string
	if len(parts) > 1 {
		roleName = parts[len(parts)-1]
	}

	return &common.IamRoleReference{
		Arn:      arn,
		RoleName: &roleName,
		Region:   region,
	}
}

// createVpcReference creates a VPC reference with subnet information
func createVpcReference(vpcID string, subnetIds []string, region string) *common.VpcReference {
	if vpcID == "" {
		return nil
	}

	return &common.VpcReference{
		Id:        vpcID,
		Region:    region,
		SubnetIds: subnetIds,
	}
}

// createSecurityGroupReference creates a security group reference
func createSecurityGroupReference(sgID, region string) *common.SecurityGroupReference {
	if sgID == "" {
		return nil
	}

	return &common.SecurityGroupReference{
		Id:     sgID,
		Region: region,
	}
}

// createKmsKeyReference creates a KMS key reference from an ARN
func createKmsKeyReference(keyArn, region string) *common.KmsKeyReference {
	if keyArn == "" {
		return nil
	}

	// Extract key ID from ARN
	parts := strings.Split(keyArn, "/")
	var keyID string
	if len(parts) > 1 {
		keyID = parts[len(parts)-1]
	} else {
		// If no "/" found, try to extract from colon-separated parts
		parts = strings.Split(keyArn, ":")
		if len(parts) > 0 {
			keyID = parts[len(parts)-1]
		}
	}

	return &common.KmsKeyReference{
		Arn:    keyArn,
		KeyId:  keyID,
		Region: region,
	}
}

// createCloudWatchLogReference creates a CloudWatch log reference from log group name
func createCloudWatchLogReference(logGroupName, clusterARN, region string) *common.CloudWatchLogReference {
	if logGroupName == "" || clusterARN == "" {
		return nil
	}

	logGroupARN, err := utils.BuildRelatedARN(clusterARN, "logs", region, "log-group:"+logGroupName)
	if err != nil {
		return nil
	}

	return &common.CloudWatchLogReference{
		Arn:          logGroupARN,
		LogGroupName: logGroupName,
		Region:       region,
	}
}

// discoverEksResourceReferences discovers and sets AWS resource references for the EKS cluster
func discoverEksResourceReferences(cluster *eksTypes.Cluster, nodeGroups interface{}, resources *eksfern.EksResourceInfo, region string) {
	var iamRoles []*common.IamRoleReference
	var securityGroups []*common.SecurityGroupReference
	var ec2Instances []*ec2.Ec2Instance
	var kmsKeys []*common.KmsKeyReference
	var cloudWatchLogs []*common.CloudWatchLogReference

	// Track discovered resources to avoid duplicates
	discoveredRoles := make(map[string]bool)
	discoveredSGs := make(map[string]bool)
	discoveredKeys := make(map[string]bool)
	discoveredLogs := make(map[string]bool)

	// Discover IAM role from cluster service role
	if cluster.RoleArn != nil {
		roleRef := createIamRoleReference(*cluster.RoleArn, region)
		if roleRef != nil && !discoveredRoles[roleRef.Arn] {
			iamRoles = append(iamRoles, roleRef)
			discoveredRoles[roleRef.Arn] = true
		}
	}

	// Discover VPC and security groups from VPC config
	if cluster.ResourcesVpcConfig != nil {
		// Set VPC reference
		if cluster.ResourcesVpcConfig.VpcId != nil {
			vpcRef := createVpcReference(*cluster.ResourcesVpcConfig.VpcId, cluster.ResourcesVpcConfig.SubnetIds, region)
			if vpcRef != nil {
				resources.Vpc = vpcRef
			}
		}

		// Discover security groups
		for _, sgID := range cluster.ResourcesVpcConfig.SecurityGroupIds {
			if !discoveredSGs[sgID] {
				sgRef := createSecurityGroupReference(sgID, region)
				if sgRef != nil {
					securityGroups = append(securityGroups, sgRef)
					discoveredSGs[sgID] = true
				}
			}
		}

		// Add cluster security group if present
		if cluster.ResourcesVpcConfig.ClusterSecurityGroupId != nil {
			sgID := *cluster.ResourcesVpcConfig.ClusterSecurityGroupId
			if !discoveredSGs[sgID] {
				sgRef := createSecurityGroupReference(sgID, region)
				if sgRef != nil {
					securityGroups = append(securityGroups, sgRef)
					discoveredSGs[sgID] = true
				}
			}
		}
	}

	// Discover KMS keys from encryption config
	if cluster.EncryptionConfig != nil {
		for _, encryptionCfg := range cluster.EncryptionConfig {
			if encryptionCfg.Provider != nil && encryptionCfg.Provider.KeyArn != nil {
				keyRef := createKmsKeyReference(*encryptionCfg.Provider.KeyArn, region)
				if keyRef != nil && !discoveredKeys[keyRef.Arn] {
					kmsKeys = append(kmsKeys, keyRef)
					discoveredKeys[keyRef.Arn] = true
				}
			}
		}
	}

	// Discover CloudWatch logs from logging config
	if cluster.Logging != nil && cluster.Logging.ClusterLogging != nil {
		for _, logConfig := range cluster.Logging.ClusterLogging {
			if logConfig.Enabled != nil && *logConfig.Enabled {
				// Construct log group name for EKS cluster
				logGroupName := fmt.Sprintf("/aws/eks/%s/cluster", *cluster.Name)
				if !discoveredLogs[logGroupName] {
					logRef := createCloudWatchLogReference(logGroupName, *cluster.Arn, region)
					if logRef != nil {
						cloudWatchLogs = append(cloudWatchLogs, logRef)
						discoveredLogs[logGroupName] = true
					}
				}
			}
		}
	}

	// Note: NodeGroup resource discovery disabled (NodeGroup type not available)

	// Set discovered resources
	if len(iamRoles) > 0 {
		resources.IamRoles = iamRoles
	}
	if len(securityGroups) > 0 {
		resources.SecurityGroups = securityGroups
	}
	if len(ec2Instances) > 0 {
		resources.Ec2Instances = ec2Instances
	}
	if len(kmsKeys) > 0 {
		resources.KmsKeys = kmsKeys
	}
	if len(cloudWatchLogs) > 0 {
		resources.CloudWatchLogs = cloudWatchLogs
	}
}

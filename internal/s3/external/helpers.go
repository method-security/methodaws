package s3

import (
	"net"
	"net/url"
	"strings"
)

// parseBucketURL extracts the S3 bucket name and (if derivable) the region
// from common S3 URL forms and custom domains (CNAMEs) pointing to S3.
//
// Supported examples:
//   - https://bucket.s3.us-east-1.amazonaws.com
//   - https://bucket.s3.amazonaws.com
//   - https://sub.domain.bucket.s3.us-east-1.amazonaws.com (buckets with subdomains)
//   - https://s3.us-east-1.amazonaws.com/bucket
//   - https://s3.amazonaws.com/bucket
//   - http://bucket.s3-website-us-east-1.amazonaws.com
//   - https://bucket.s3-accelerate.amazonaws.com
//   - https://custom-domain.example.com (CNAME to S3)
//   - (no scheme) bucket.s3.us-west-2.amazonaws.com
//
// Region rules:
//   - Virtual-hosted regional (bucket.s3.<region>.*) → region extracted
//   - Path-style regional (s3.<region>.* /bucket)   → region extracted
//   - Global endpoints (s3.amazonaws.com, s3-accelerate) → region empty
//   - Website endpoints (s3-website-<region>) → region extracted
//   - Custom domains → region empty (not derivable from URL)
//
// Returns: (bucketName, region). Region may be "" if not derivable.
func parseBucketURL(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}

	// Ensure we can parse even if scheme is missing
	u := ensureURL(raw)

	// Strip userinfo, port; isolate host labels and first path segment
	host := strings.ToLower(u.Host)
	if host == "" {
		return "", ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	labels, isAwsEndpoint := s3EndpointLabels(host)

	// If not a standard AWS endpoint, treat as custom domain (CNAME) pointing to S3
	if !isAwsEndpoint {
		// For custom domains, the entire host is typically the bucket name
		// and we can't determine the region from the URL
		return cleanupBucket(host), ""
	}

	if len(labels) == 0 {
		return "", ""
	}

	// First path segment (for path-style)
	pathSeg := firstPathSegment(u.Path)

	// Path-style endpoints put the service before the region and bucket in the path.
	if labels[0] == "s3" || labels[0] == "s3-external-1" || labels[0] == "s3-dualstack" {
		if pathSeg == "" {
			return "", ""
		}
		region, ok := pathStyleRegion(labels)
		if !ok {
			return "", ""
		}
		return cleanupBucket(pathSeg), region
	}

	// Virtual-hosted endpoints put one of the S3 service forms after the bucket name.
	for index, label := range labels {
		if index == 0 {
			continue
		}
		region, ok := virtualHostedRegion(label, labels[index+1:])
		if ok {
			return cleanupBucket(strings.Join(labels[:index], ".")), region
		}
	}

	// Not recognized as S3 bucket URL
	return "", ""
}

func s3EndpointLabels(host string) ([]string, bool) {
	for _, suffix := range []string{"amazonaws.com.cn", "amazonaws.com"} {
		prefix, found := strings.CutSuffix(host, "."+suffix)
		if found && prefix != "" {
			return strings.Split(prefix, "."), true
		}
	}
	return nil, false
}

func pathStyleRegion(labels []string) (string, bool) {
	switch {
	case len(labels) == 1 && (labels[0] == "s3" || labels[0] == "s3-external-1"):
		return "", true
	case len(labels) == 2 && labels[0] == "s3":
		return labels[1], true
	case len(labels) == 3 && labels[0] == "s3" && labels[1] == "dualstack":
		return labels[2], true
	case len(labels) == 2 && labels[0] == "s3-dualstack":
		return labels[1], true
	default:
		return "", false
	}
}

func virtualHostedRegion(serviceLabel string, trailingLabels []string) (string, bool) {
	switch {
	case serviceLabel == "s3" && len(trailingLabels) == 0:
		return "", true
	case serviceLabel == "s3" && len(trailingLabels) == 1:
		return trailingLabels[0], true
	case serviceLabel == "s3" && len(trailingLabels) == 2 && trailingLabels[0] == "dualstack":
		return trailingLabels[1], true
	case serviceLabel == "s3-accelerate" && len(trailingLabels) == 0:
		return "", true
	case serviceLabel == "s3-accelerate" && len(trailingLabels) == 1 && trailingLabels[0] == "dualstack":
		return "", true
	case serviceLabel == "s3-website" && len(trailingLabels) == 1:
		return trailingLabels[0], true
	case strings.HasPrefix(serviceLabel, "s3-website-") && len(trailingLabels) == 0:
		return strings.TrimPrefix(serviceLabel, "s3-website-"), true
	default:
		return "", false
	}
}

func ensureURL(raw string) *url.URL {
	// Add scheme if missing so url.Parse sees Host
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Fallback minimal parse
		return &url.URL{Host: raw}
	}
	return u
}

func firstPathSegment(p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	seg := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		seg = p[:i]
	}
	// ignore query/fragment (already stripped by url.Parse)
	return seg
}

func cleanupBucket(b string) string {
	// Defensive cleanup; bucket DNS-style names shouldn't contain '?' or trailing '/'
	b = strings.TrimSpace(b)
	b = strings.TrimSuffix(b, "/")
	if i := strings.IndexByte(b, '?'); i >= 0 {
		b = b[:i]
	}
	return b
}

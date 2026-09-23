module github.com/Method-Security/methodaws

go 1.26.5

require (
	github.com/Method-Security/pkg v0.1.1
	github.com/aws/aws-sdk-go-v2 v1.44.0
	github.com/aws/aws-sdk-go-v2/config v1.32.40
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.37.8
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.67.6
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.321.3
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.36.8
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.58.9
	github.com/aws/aws-sdk-go-v2/service/iam v1.59.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.101.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.4
	github.com/aws/aws-sdk-go-v2/service/s3control v1.73.8
	github.com/aws/aws-sdk-go-v2/service/sts v1.46.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.77.7
	github.com/google/uuid v1.6.0
	github.com/palantir/pkg/datetime v1.4.0
	github.com/palantir/witchcraft-go-logging v1.70.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
	golang.org/x/net v0.58.0
	k8s.io/api v0.36.4
	k8s.io/apimachinery v0.36.4
	k8s.io/client-go v0.36.4
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.40 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-openapi/jsonpointer v0.23.2 // indirect
	github.com/go-openapi/jsonreference v0.21.6 // indirect
	github.com/go-openapi/swag v0.25.5 // indirect
	github.com/go-openapi/swag/cmdutils v0.25.5 // indirect
	github.com/go-openapi/swag/conv v0.25.5 // indirect
	github.com/go-openapi/swag/fileutils v0.25.5 // indirect
	github.com/go-openapi/swag/jsonname v0.26.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.5 // indirect
	github.com/go-openapi/swag/loading v0.25.5 // indirect
	github.com/go-openapi/swag/mangling v0.25.5 // indirect
	github.com/go-openapi/swag/netutils v0.25.5 // indirect
	github.com/go-openapi/swag/stringutils v0.25.5 // indirect
	github.com/go-openapi/swag/typeutils v0.25.5 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.5 // indirect
	github.com/gofrs/flock v0.13.1 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/palantir/pkg/safejson v1.2.0 // indirect
	github.com/palantir/pkg/safeyaml v1.2.0 // indirect
	github.com/palantir/pkg/uuid v1.3.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260317180543-43fb72c5454a // indirect
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3 // indirect
	sigs.k8s.io/json v0.0.0-20260909141634-11ed52e25bc5 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.3 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.39 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.40 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.41 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.42.8
	github.com/aws/aws-sdk-go-v2/service/eks v1.91.1
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.40 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.41 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.124.5
	github.com/aws/aws-sdk-go-v2/service/route53 v1.65.10
	github.com/aws/aws-sdk-go-v2/service/sso v1.34.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.39.0 // indirect
	github.com/aws/smithy-go v1.28.2
	github.com/fatih/color v1.19.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/palantir/pkg v1.1.0 // indirect
	github.com/palantir/pkg/bytesbuffers v1.3.0 // indirect
	github.com/palantir/pkg/safelong v1.3.0 // indirect
	github.com/palantir/pkg/transform v1.2.0 // indirect
	github.com/palantir/witchcraft-go-error v1.46.0 // indirect
	github.com/palantir/witchcraft-go-params v1.42.0 // indirect
	github.com/palantir/witchcraft-go-tracing v1.44.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	sigs.k8s.io/aws-iam-authenticator v0.7.20
)

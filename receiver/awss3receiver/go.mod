module github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awss3receiver

go 1.22.0

require (
	github.com/aws/aws-sdk-go-v2 v1.34.0
	github.com/aws/aws-sdk-go-v2/config v1.29.2
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.54
	github.com/aws/aws-sdk-go-v2/service/s3 v1.74.1
	github.com/open-telemetry/opamp-go v0.18.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampcustommessages v0.118.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v0.118.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/component/componenttest v0.118.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/confmap v1.24.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/consumer v1.24.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/consumer/consumertest v0.118.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/pdata v1.24.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/receiver v0.118.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/receiver/receivertest v0.118.1-0.20250123125445-24f88da7b583
	go.opentelemetry.io/collector/semconv v0.118.1-0.20250123125445-24f88da7b583
	go.uber.org/goleak v1.3.0
	go.uber.org/multierr v1.11.0
	go.uber.org/zap v1.27.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.8 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.55 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.10 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.2 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/collector/pipeline v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/collector/receiver/xreceiver v0.118.1-0.20250123125445-24f88da7b583 // indirect
	go.opentelemetry.io/otel v1.34.0 // indirect
	go.opentelemetry.io/otel/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/sdk v1.34.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/trace v1.34.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/grpc v1.69.4 // indirect
	google.golang.org/protobuf v1.36.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampcustommessages => ../../extension/opampcustommessages

module github.com/open-telemetry/opentelemetry-collector-contrib/extension/sumologicextension

go 1.22.0

require (
	github.com/Showmax/go-fqdn v1.0.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/shirou/gopsutil/v4 v4.24.12
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v0.116.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/component/componenttest v0.116.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/config/confighttp v0.116.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/config/configopaque v1.22.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/extension v0.116.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/extension/auth v0.116.1-0.20241220212031-7c2639723f67
	go.opentelemetry.io/collector/featuregate v1.22.1-0.20241220212031-7c2639723f67
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.69.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ebitengine/purego v0.8.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/collector/client v1.22.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/collector/config/configauth v0.116.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.22.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.116.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/collector/config/configtls v1.22.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/collector/pdata v1.22.1-0.20241220212031-7c2639723f67 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.56.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	google.golang.org/protobuf v1.36.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace go.opentelemetry.io/collector/scraper/scraperhelper v0.116.0 => go.opentelemetry.io/collector/scraper/scraperhelper v0.0.0-20250106214556-67fdcd1f4267

replace go.opentelemetry.io/collector/extension/xextension v0.116.0 => go.opentelemetry.io/collector/extension/xextension v0.0.0-20250106214556-67fdcd1f4267

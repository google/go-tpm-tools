module github.com/google/go-tpm-tools/cmd

go 1.24.0

toolchain go1.24.4

require (
	cloud.google.com/go/compute/metadata v0.8.0
	cloud.google.com/go/logging v1.13.0
	github.com/containerd/containerd v1.7.28
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/golang/protobuf v1.5.4
	github.com/google/go-sev-guest v0.13.0
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.5
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/go-tpm-tools/verifier v0.4.4
	github.com/spf13/cobra v1.10.1
	golang.org/x/oauth2 v0.31.0
	google.golang.org/api v0.249.0
	google.golang.org/grpc v1.75.0
	google.golang.org/protobuf v1.36.9
)

require (
	cloud.google.com/go v0.122.0 // indirect
	cloud.google.com/go/auth v0.16.5 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/confidentialcomputing v1.10.0 // indirect
	cloud.google.com/go/longrunning v0.6.7 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-eventlog v0.0.2 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.63.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/time v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20250908214217-97024824d090 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250908214217-97024824d090 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250908214217-97024824d090 // indirect
)

replace (
	github.com/google/go-tpm-tools v0.4.4 => ../
	github.com/google/go-tpm-tools/verifier v0.4.4 => ../verifier
)

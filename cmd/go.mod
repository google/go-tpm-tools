module github.com/google/go-tpm-tools/cmd

go 1.24.0

toolchain go1.24.13

require (
	cloud.google.com/go/compute/metadata v0.9.0
	cloud.google.com/go/logging v1.13.1
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/golang/protobuf v1.5.4
	github.com/google/gce-tcb-verifier v0.3.1
	github.com/google/gce-tcb-verifier/gcetcbendorsement v0.0.0-20250301004354-d18ce1139be2
	github.com/google/go-configfs-tsm v0.3.3
	github.com/google/go-sev-guest v0.14.0
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.6
	github.com/google/go-tpm-tools v0.4.6
	github.com/google/go-tpm-tools/verifier v0.4.4
	github.com/spf13/cobra v1.8.1
	golang.org/x/oauth2 v0.34.0
	google.golang.org/api v0.265.0
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/confidentialcomputing v1.11.0 // indirect
	cloud.google.com/go/longrunning v0.8.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260307011055-895ec9019dd7 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.5 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-eventlog v0.0.3-0.20260305053119-5cd85087f9f9 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.11 // indirect
	github.com/googleapis/gax-go/v2 v2.17.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/term v0.39.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260203192932-546029d2fa20 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
)

replace (
	github.com/google/go-tpm-tools v0.4.4 => ../
	github.com/google/go-tpm-tools/verifier v0.4.4 => ../verifier
)

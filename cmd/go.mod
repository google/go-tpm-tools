module github.com/google/go-tpm-tools/cmd

go 1.21

require (
	cloud.google.com/go/compute/metadata v0.5.0
	cloud.google.com/go/logging v1.10.0
	github.com/containerd/containerd v1.7.16
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/golang/protobuf v1.5.4
	github.com/google/go-sev-guest v0.11.1
	github.com/google/go-tdx-guest v0.3.2-0.20240902060211-1f7f7b9b42b9
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/go-tpm-tools/verifier v0.4.4
	github.com/spf13/cobra v1.8.0
	golang.org/x/oauth2 v0.21.0
	google.golang.org/api v0.189.0
	google.golang.org/grpc v1.64.1
	google.golang.org/protobuf v1.34.2
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/auth v0.7.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.3 // indirect
	cloud.google.com/go/confidentialcomputing v1.6.0 // indirect
	cloud.google.com/go/longrunning v0.5.9 // indirect
	github.com/containerd/ttrpc v1.2.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/gce-tcb-verifier v0.2.3-0.20240905212129-12f728a62786 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-eventlog v0.0.2-0.20241003021507-01bb555f7cba // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.13.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/exp v0.0.0-20240531132922-fd00a4e0eefc // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240722135656-d784300faade // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade // indirect
)

replace (
	github.com/google/go-tpm-tools v0.4.4 => ../
	github.com/google/go-tpm-tools/verifier v0.4.4 => ../verifier
)

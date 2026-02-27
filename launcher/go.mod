module github.com/google/go-tpm-tools/launcher

go 1.24.0

toolchain go1.24.8

require (
	cloud.google.com/go/compute/metadata v0.8.0
	cloud.google.com/go/logging v1.13.0
	cos.googlesource.com/cos/tools.git v0.0.0-20250414225215-0cf736c0714c
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/containerd/containerd v1.7.23
	github.com/containerd/containerd/v2 v2.0.1
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/google/go-cmp v0.7.0
	github.com/google/go-eventlog v0.0.3-0.20250820210646-0f4d84deece4
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.6
	github.com/google/go-tpm-tools v0.4.6
	github.com/google/go-tpm-tools/verifier v0.4.4
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/opencontainers/runtime-spec v1.2.0
	golang.org/x/oauth2 v0.30.0
	google.golang.org/api v0.247.0
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c
	google.golang.org/grpc v1.74.2
	google.golang.org/protobuf v1.36.9
)

require (
	cloud.google.com/go v0.120.0 // indirect
	cloud.google.com/go/auth v0.16.4 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/confidentialcomputing v1.9.3-0.20250902151313-51583bd5c9b8 // indirect
	cloud.google.com/go/longrunning v0.6.7 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20231105174938-2b5cbb29f3e2 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260227215608-998bdbe721d1 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/continuity v0.4.4 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.0 // indirect
	github.com/containerd/ttrpc v1.2.6 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/selinux v1.11.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
)

replace (
	github.com/google/go-tpm-tools v0.4.4 => ../
	github.com/google/go-tpm-tools/verifier v0.4.4 => ../verifier
)

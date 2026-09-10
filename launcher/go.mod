module github.com/google/go-tpm-tools/launcher

go 1.26.6

require (
	cloud.google.com/go/auth v0.20.0
	cloud.google.com/go/compute/metadata v0.9.0
	cloud.google.com/go/logging v1.13.2
	cos.googlesource.com/cos/tools.git v0.0.0-20260828164205-7c1f394ced14
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260706204617-c9f710ef3461
	github.com/GoogleCloudPlatform/key-protection-module v0.0.0-20260604222613-9d1fbac80fd7
	github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service v0.0.0-20260604222613-9d1fbac80fd7
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/containerd/containerd v1.7.23
	github.com/containerd/containerd/v2 v2.3.2
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/google/go-cmp v0.7.0
	github.com/google/go-eventlog v0.0.3-0.20260617163629-883cc5652c69
	github.com/google/go-nvattest-tools v0.0.0-20260714083801-bf44c37ba22c
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.9-0.20260601203525-bc0d334a930f
	github.com/google/go-tpm-tools/agent v0.0.0-20260601203525-bc0d334a930f
	github.com/google/go-tpm-tools/keymanager v0.4.4
	github.com/google/go-tpm-tools/verifier v0.4.4
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/runtime-spec v1.3.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/api v0.283.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260209202127-80ab13bee0bf.1 // indirect
	buf.build/go/protovalidate v1.1.3 // indirect
	cel.dev/expr v0.25.2 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/confidentialcomputing v1.17.0 // indirect
	cloud.google.com/go/longrunning v0.8.0 // indirect
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20231105174938-2b5cbb29f3e2 // indirect
	github.com/Microsoft/go-winio v0.6.3-0.20251027160822-ad3df93bed29 // indirect
	github.com/Microsoft/hcsshim v0.15.0-rc.1 // indirect
	github.com/NVIDIA/go-nvml v0.13.0-1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/cgroups/v3 v3.1.3 // indirect
	github.com/containerd/containerd/api v1.11.1 // indirect
	github.com/containerd/continuity v0.5.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.4 // indirect
	github.com/containerd/ttrpc v1.2.8 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/cel-go v0.27.0 // indirect
	github.com/google/go-attestation v0.6.4 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.16 // indirect
	github.com/googleapis/gax-go/v2 v2.22.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mdlayher/vsock v1.2.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/selinux v1.13.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.68.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/exp v0.0.0-20250813145105-42675adae3e6 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace (
	github.com/google/go-tpm-tools v0.4.6 => ../
	github.com/google/go-tpm-tools/agent => ../agent
	github.com/google/go-tpm-tools/keymanager v0.4.4 => ../keymanager
	github.com/google/go-tpm-tools/verifier v0.4.4 => ../verifier
)

// cos-tools upgrades containerd/v2 to v2.3.2 which requires runtime-spec v1.3.0,
// but containerd v1.7.23 (used by launcher) is incompatible with runtime-spec v1.3.0
// due to LinuxPids.Limit changing from int64 to *int64.
replace github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.2.0

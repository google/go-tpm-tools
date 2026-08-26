module github.com/google/go-tpm-tools

go 1.26

toolchain go1.26.5

require (
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260706204617-c9f710ef3461
	github.com/google/go-attestation v0.6.4
	github.com/google/go-cmp v0.7.0
	github.com/google/go-sev-guest v0.14.0
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.8
	github.com/google/logger v1.1.1
	google.golang.org/protobuf v1.36.11
)

require github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect

require (
	github.com/google/go-eventlog v0.0.3-0.20260617163629-883cc5652c69
	github.com/google/uuid v1.6.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

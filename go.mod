module github.com/google/go-tpm-tools

go 1.24.0

toolchain go1.24.4

require (
	github.com/google/go-attestation v0.5.1
	github.com/google/go-cmp v0.7.0
	github.com/google/go-configfs-tsm v0.3.3
	github.com/google/go-sev-guest v0.13.0
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm v0.9.5
	github.com/google/logger v1.1.1
	google.golang.org/protobuf v1.36.9
)

require github.com/stretchr/testify v1.11.1 // indirect

require (
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-eventlog v0.0.2
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

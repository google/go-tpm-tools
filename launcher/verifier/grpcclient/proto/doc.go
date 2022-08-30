// Package proto contains protocol buffers for the attestation.
//
// # Generating Protocol Buffer Code
//
// Anytime the Protocol Buffer definitions change, the generated Go code must be
// regenerated. This can be done with "go generate". Just run:
//
//	go generate ./...
//
// in the ./launcher directory. Or if using Go 1.18 or later, you can just run
//
//	go generate ./launcher/...
//
// in the root directory.
//
// Upstream documentation:
// https://developers.google.com/protocol-buffers/docs/reference/go-generated
//
// # Code Generation Dependencies
//
// google/api/annotations.proto is copied from
// https://github.com/googleapis/googleapis/blob/master/google/api/annotations.proto
//
// google/api/http.proto is copied from
// https://github.com/googleapis/googleapis/blob/master/google/api/http.proto
//
// To generate the Go code, your system must have "protoc" installed. See:
// https://github.com/protocolbuffers/protobuf#protocol-compiler-installation
//
// The "protoc-gen-go" tool must also be installed. To install it, run:
//
//	go install google.golang.org/protobuf/cmd/protoc-gen-go
//
// Then, install "protoc-gen-go-grpc" plugin, run:
//
//	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
package proto

//go:generate protoc -I=../../../../proto -I=. --go_out=. --go-grpc_out=require_unimplemented_servers=false,module=github.com/google/go-tpm-tools/launcher/internal/verifier/proto:. --go_opt=module=github.com/google/go-tpm-tools/launcher/internal/verifier/proto  service.proto

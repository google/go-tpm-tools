// Package proto contains protocol buffers that are exchanged between the client
// and server.
//
// Generating Protocol Buffer Code
//
// Anytime the Protocol Buffer definitions change, the generated Go code must be
// regenerated. This can be done with "go generate". Just run:
//   go generate ./...
//
// Upstream documentation:
// https://developers.google.com/protocol-buffers/docs/reference/go-generated
//
// Code Generation Dependencies
//
// To generate the Go code, your system must have "protoc" installed. See:
// https://github.com/protocolbuffers/protobuf#protocol-compiler-installation
//
// The "protoc-gen-go" tool must also be installed. To install it, run:
//   go install google.golang.org/protobuf/cmd/protoc-gen-go
package proto

//go:generate protoc --go_out=. --go_opt=module=github.com/google/go-tpm-tools/proto tpm.proto attest.proto

// Package proto contains protocol buffers that are exchanged between the client
// and server. Note, some of these types have additional helper methods.
package proto

//go:generate protoc --go_out=. --go_opt=module=github.com/google/go-tpm-tools/proto tpm.proto

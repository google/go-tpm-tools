#!/bin/bash
# Re-generate the Go code for keymanager protos.

# Generate algorithms.pb.go
protoc -I. --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/algorithms.proto

# Generate key_claims.pb.go
# Uses -I. so that "keymanager/km_common/proto/algorithms.proto" import works in key_claims.proto
protoc -I. --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/key_claims.proto

#!/bin/bash
# Re-generate the Go code for keymanager protos.

# Generate algorithms.pb.go
protoc -I. -Iproto --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/algorithms.proto
# Generate key_claims.pb.go
protoc -I. -Iproto --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/key_claims.proto
# Generate payload.pb.go
protoc -I. -Iproto --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/payload.proto
# Generate api.pb.go
protoc -I. -Iproto --go_out=. --go_opt=paths=source_relative keymanager/workload_service/proto/api.proto
# Generate status.pb.go
protoc -I. -Iproto --go_out=. --go_opt=paths=source_relative keymanager/km_common/proto/status.proto

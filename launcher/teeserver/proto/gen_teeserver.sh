#!/bin/bash

protoc -I. -I../../../ -I../../../proto  -I`go list -m -f "{{.Dir}}" github.com/GoogleCloudPlatform/key-protection-module` --go_out=. --go_opt=module=github.com/google/go-tpm-tools/launcher/teeserver/proto  --experimental_allow_proto3_optional teeserver.proto

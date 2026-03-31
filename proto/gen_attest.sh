#!/bin/bash

protoc -I. -I`go list -m -f "{{.Dir}}" github.com/google/go-sev-guest` -I`go list -m -f "{{.Dir}}" github.com/google/go-tdx-guest` -I$(go list -m -f "{{.Dir}}" github.com/GoogleCloudPlatform/confidential-space/server)/proto --go_out=. --go_opt=module=github.com/google/go-tpm-tools/proto  --experimental_allow_proto3_optional attest.proto

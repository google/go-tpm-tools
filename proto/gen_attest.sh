#!/bin/bash

protoc -I. -I`go list -m -f "{{.Dir}}" github.com/google/go-sev-guest` -I`go list -m -f "{{.Dir}}" github.com/google/go-tdx-guest` --go_out=. --go_opt=module=github.com/google/go-tpm-tools/proto attest.proto

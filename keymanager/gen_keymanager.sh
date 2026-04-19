#!/bin/bash
# Re-generate the Go code for keymanager protos.

cd "$(dirname "$0")" || exit 1

go run github.com/bufbuild/buf/cmd/buf@v1.68.2 generate . --template buf.gen.yaml

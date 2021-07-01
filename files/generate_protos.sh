#!/bin/sh

set -eu -o pipefail
shopt -s failglob

# We want this script to work regardless of the current working directory.
# Make the current directory the root of the repository
cd "$(dirname "$0")/.."

# TODO(joerichey): Download and cache the protoc compiler, rather than using
# whatever version is present on the system.

# Generate the Protocol Buffers in the correct locations
protoc --go_out=. --go_opt=module=github.com/google/go-tpm-tools **/*.proto
#!/bin/bash
# Integration test script for keymanager Go <-> Rust FFI.
# Runs inside a Linux container (podman/docker) to test the full stack:
#   Go HTTP server -> CGO bridge -> Rust KCC -> BoringSSL
#
# Usage:
#   ./integration_test.sh          # auto-detect podman or docker
#   CONTAINER_RT=docker ./integration_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Auto-detect container runtime
if [ -z "${CONTAINER_RT:-}" ]; then
    if command -v podman &>/dev/null; then
        CONTAINER_RT=podman
    elif command -v docker &>/dev/null; then
        CONTAINER_RT=docker
    else
        echo "ERROR: Neither podman nor docker found. Install one to run integration tests."
        exit 1
    fi
fi

echo "=== Keymanager Integration Test ==="
echo "Container runtime: $CONTAINER_RT"
echo "Repository root: $REPO_ROOT"
echo ""

# --privileged is required for memfd_secret (syscall 447) used by the Vault
$CONTAINER_RT run --rm --privileged \
    -v "$REPO_ROOT:/workspace:Z" \
    -w /workspace/keymanager \
    rust:latest \
    bash -exc '
        echo "=== Installing dependencies ==="
        apt-get update -qq && apt-get install -y -qq cmake ninja-build clang golang-go > /dev/null 2>&1
        cargo install bindgen-cli 2>&1 | tail -1

        # Check Go version (need 1.23+, apt may be older)
        GO_VERSION=$(go version | grep -oP "go\K[0-9]+\.[0-9]+")
        echo "System Go version: $GO_VERSION"

        # If system Go is too old, install a newer one
        GO_REQUIRED="1.23"
        if [ "$(printf "%s\n%s" "$GO_REQUIRED" "$GO_VERSION" | sort -V | head -1)" != "$GO_REQUIRED" ]; then
            echo "System Go too old, installing Go 1.23..."
            curl -sSfL https://go.dev/dl/go1.23.6.linux-amd64.tar.gz | tar -C /usr/local -xzf -
            export PATH="/usr/local/go/bin:$PATH"
        fi

        echo "Using Go: $(go version)"
        echo "Using Rust: $(rustc --version)"
        echo "Using Cargo: $(cargo --version)"
        echo ""

        echo "=== Building Rust workspace (release) ==="
        cargo build --release 2>&1

        echo ""
        echo "=== Locating BoringSSL libraries ==="
        # Find the BoringSSL build output directory (has a hash in the path)
        BSSL_BUILD_DIR=$(find target/release/build -path "*/bssl-sys-*/out/build" -type d | head -1)
        if [ -z "$BSSL_BUILD_DIR" ]; then
            echo "ERROR: Could not find BoringSSL build directory"
            exit 1
        fi
        echo "BoringSSL build dir: $BSSL_BUILD_DIR"

        # Collect all BoringSSL library search paths
        BSSL_LIB_PATHS=""
        for subdir in "" "/crypto" "/ssl" "/rust/bssl-sys"; do
            dir="$BSSL_BUILD_DIR$subdir"
            if [ -d "$dir" ]; then
                BSSL_LIB_PATHS="$BSSL_LIB_PATHS -L$dir"
            fi
        done
        echo "BoringSSL link paths: $BSSL_LIB_PATHS"

        # Verify key libraries exist
        echo "Checking libraries..."
        ls -la target/release/libws_key_custody_core.a
        ls -la target/release/libkps_key_custody_core.a
        find "$BSSL_BUILD_DIR" -name "libcrypto.a" -o -name "libssl.a" -o -name "librust_wrapper.a" | head -5

        echo ""
        echo "=== Running Rust tests ==="
        cargo test 2>&1

        echo ""
        echo "=== Running Go integration tests ==="
        export CGO_ENABLED=1
        export CGO_LDFLAGS="$BSSL_LIB_PATHS"

        echo "CGO_LDFLAGS=$CGO_LDFLAGS"

        # Run WSD KCC integration tests
        echo "--- WSD KCC (Go -> Rust binding key generation) ---"
        go test -v -tags integration ./workload_service/key_custody_core/

        # Run KPS KCC integration tests
        echo "--- KPS KCC (Go -> Rust KEM key generation) ---"
        go test -v -tags integration ./key_protection_service/key_custody_core/

        # Run WSD KOL end-to-end integration tests (HTTP -> CGO -> Rust)
        echo "--- WSD KOL E2E (HTTP server -> CGO -> Rust) ---"
        go test -v -tags integration ./workload_service/

        # Also run the unit tests to make sure everything works together
        echo "--- Unit tests ---"
        go test -v ./workload_service/ ./key_protection_service/

        echo ""
        echo "=== ALL TESTS PASSED ==="
    '

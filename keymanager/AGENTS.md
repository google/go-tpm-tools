# KeyManager Agent Instructions

This document provides instructions for modifying the `keymanager` component of `go-tpm-tools`.

## Project Structure

The codebase is logically divided into several core modules:
*   **`km_common/`**: Shared Rust cryptographic utilities, types, and safe memory abstractions used across services.
*   **`key_protection_service/`**: Implements the Key Protection Service (KPS) logic, responsible for secure sealing and unsealing of material bound to TPMs.
*   **`workload_service/`**: Implements the Workload Service (WS), providing APIs for workload identity, signing, and decryption.
*   **`cmd/agent/`**: Contains the Go entrypoint (`main.go`) and Dockerfile for the KeyManagement Agent (KMA).

## Local Development Prerequisites

To fully build and test the `keymanager` component locally, ensure you have the following installed:
*   **Rust & Cargo:** Standard Rust toolchain (e.g., via rustup).
*   **Go:** Modern Go toolchain.
*   **C/C++ Toolchain:** `cmake`, `clang`, `gcc`, `pkg-config`, and `libssl-dev` (for building BoringSSL and FFI bindings).
*   **`cbindgen`:** Required for regenerating C headers. Install via: `cargo install bindgen-cli cbindgen`.
*   **Protobuf:** `protoc` compiler and the Go plugin (`go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`).

## Polyglot Environment and Building

The `keymanager` component is a polyglot project bridging Rust core logic, C-bindings, and a Go service layer. 

*   **Rust:** The core cryptographic and custody logic (e.g., in `key_protection_service` and `workload_service`) is written in Rust. You will find a root `Cargo.toml` file in this directory. Use standard Cargo commands (e.g., `cargo build`, `cargo test`) to build and test the Rust crates.
*   **Go:** The service layers and HTTP servers are written in Go. Use `go build ./...` and `go test ./...` to build and test the Go wrappers and services.
*   **C/FFI:** The Go and Rust layers communicate via C bindings. When modifying the Rust FFI interfaces, ensure you regenerate and update the C headers using the provided `generate_ffi_headers.sh` script.

## Error Handling and FFI Standardization

A unified, type-safe reporting mechanism is enforced across Rust, C, and Go layers.

*   **Standardized Status Enum:** Always utilize the standardized `keymanager.Status` Protobuf enum across all layers of the system. Do not use legacy negative `i32` error codes or ad-hoc error enums.
*   **Rust FFI:** The Rust core implementations must return the `Status` enum directly.
*   **C-Bindings:** C function signatures in headers (like `kps_key_custody_core.h`) must return `Status` instead of `int32_t`.
*   **Go CGO:** In the Go layer, CGO wrappers must interpret the new Status return codes and convert them into idiomatic Go errors using the `ToStatus()` helper. 
*   **HTTP Mapping:** The Go server automatically maps these standardized FFI errors to appropriate HTTP status codes (e.g., `ERROR_NOT_FOUND` to 404).

## Protobuf APIs

The workload service APIs are backed by protocol buffers.

*   API definitions are located in `proto/api.proto` (relative to the repository root).
*   **Regenerating Bindings:** If you modify the `.proto` files, you must regenerate the Go bindings by running the following from the repository root:
    ```bash
    go generate ./... ./agent/... ./cmd/... ./launcher/... ./verifier/...
    ```
*   When serializing payloads, use `protojson` for deterministic and exact JSON compatibility.
*   Message validation rules are enforced using `buf.validate` directly on the protobuf messages.

## Managing Dependencies

*   **Go:** Use `go get` and `go mod tidy` for Go dependencies.
*   **Rust:** Use `cargo add` for Rust dependencies in `Cargo.toml`.
*   **BoringSSL:** The project uses BoringSSL to provide the `bssl-crypto` crate dependency, which is managed as a git submodule. It is automatically configured and built using the `cmake` crate in `build.rs`.

## Testing Strategy

The project employs a tiered testing strategy combining Rust unit tests, Go unit tests, and cross-layer integration tests.

### Unit Testing

*   **Rust Logic:** Unit tests for core cryptographic and custody logic reside within the Rust crates under `#[cfg(test)]` modules. Run them from the `keymanager` root or individual crate directories:
    ```bash
    cargo test
    ```
*   **Go Service Layer:** Go unit tests cover service-level logic, request validation, and API mapping. Run them using:
    ```bash
    go test -v ./...
    ```

### Integration Testing

Integration tests verify the end-to-end flow from Go, through CGO, to the Rust core.

*   **CGO Bindings:** Located in `integration_test.go` within the `key_custody_core` directories. These ensure the FFI boundary correctly handles data serialization and error mapping.
*   **Workload Service:** `keymanager/workload_service/integration_test.go` tests the full gRPC/HTTP service stack.
*   **KMA Agent:** To verify the KeyManagement Agent (KMA) container:
    ```bash
    docker build -t kma-agent -f keymanager/cmd/agent/Dockerfile .
    docker run -d --name kma-test -v /tmp/socket:/run/container_launcher kma-agent
    # Verify connectivity
    curl -s --unix-socket /tmp/socket/kmaserver.sock http://localhost/v1/capabilities
    ```

## Continuous Integration and Linters

The project enforces strict quality gates via GitHub Actions. You should run these locally before submitting changes.

### Linters

*   **Go:** Use `golangci-lint` with the project-specific configuration:
    ```bash
    golangci-lint run ./... -E stylecheck,goimports,misspell,revive,gofmt -D errcheck
    ```
*   **Rust:** Run Clippy for static analysis and check formatting:
    ```bash
    cargo clippy -- -D warnings
    cargo fmt --check
    ```
*   **CGO:** Verify that C bindings do not introduce warnings (which are treated as errors in CI):
    ```bash
    CGO_CFLAGS=-Werror CC=gcc go build ./...
    ```

### Running CI Locally

While GitHub Actions run on every PR, you can simulate the primary build and test steps:
1.  **Regenerate FFI:** `./generate_ffi_headers.sh`
2.  **Build Rust:** `cargo build --release` (inside `keymanager`)
3.  **Test All:** `go test -v ./...`

## Style Guide and Formatting

*   **Go:** Always format Go code using `go fmt ./...`.
*   **Rust:** Always format Rust code using `cargo fmt`.
*   **Lints:** Ensure all linters pass before pushing. Clippy warnings must be addressed, not suppressed.

### Log and Error Messages (Go)

All Go error messages and log lines must follow standard Go conventions:
*   **Lowercase start.** Error messages are composed in chains like `"verifying signature: parsing certificate: invalid PEM"`.
*   **No trailing period.** Sentences in error chains should not end with `.`.
*   **No "error:" or "failed to" prefixes.** The caller adds context; the message describes what was being done or what went wrong.

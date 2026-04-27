# Multi-stage Dockerfile for Keymanager (WSD)
FROM golang:1.24 AS go-builder

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install dependencies for BoringSSL and others
RUN apt-get update && apt-get install -y cmake g++ libssl-dev pkg-config clang libclang-dev
RUN cargo install bindgen-cli

WORKDIR /app
COPY . .

# Build the Rust part
RUN cd keymanager && go generate ./...

# Build the Go binary
RUN cd keymanager && go build -o /kma ./cmd/agent/main.go

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /kma /kma

ENTRYPOINT ["/kma"]

FROM golang:latest
# We need OpenSSL headers to build the simulator
RUN apt-get update && apt-get install -y \
    libssl-dev libtspi-dev protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
# We need golangci-lint for linting
ARG VERSION=1.23.7
RUN curl -SL \
    https://github.com/golangci/golangci-lint/releases/download/v${VERSION}/golangci-lint-${VERSION}-linux-amd64.tar.gz \
    --output golangci.tar.gz \
 && tar --extract --verbose \
    --file=golangci.tar.gz \
    --directory=/usr/local/bin \
    --strip-components=1 \
    --wildcards "*/golangci-lint" \
 && rm golangci.tar.gz
# We need protoc-gen-go to generate code
ENV GOBIN=/usr/local/bin/
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

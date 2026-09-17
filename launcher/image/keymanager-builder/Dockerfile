# launcher/image/keymanager-builder/Dockerfile
#
# To build and push:
# gcloud builds submit --tag us-docker.pkg.dev/confidential-space-images-dev/cs-tools/keymanager-builder:latest --project confidential-space-images-dev launcher/image/keymanager-builder/

FROM rust@sha256:0fdb1727a6c81e0811df9d67bd6defa9a4a07d2a44373ab0a017aedad9fcba3f

ARG SOURCE_DATE_EPOCH=0

ENV CMAKE_VERSION="3.28.3"
ENV BINDGEN_VERSION="0.70.0"

# Clang is required by bindgen-cli and BoringSSL's C++ FFI build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    && rm -rf /var/lib/apt/lists/*

# BoringSSL requires CMake 3.22+; Debian Bullseye packages are too old.
RUN curl -fsSL "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz" | tar -zxv -C /opt/

# Pre-compiling bindgen-cli eliminates ~4m of compilation time from presubmit runs.
RUN cargo install bindgen-cli --version "${BINDGEN_VERSION}"

ENV PATH="/opt/cmake-${CMAKE_VERSION}-linux-x86_64/bin:/root/.cargo/bin:${PATH}"

WORKDIR /workspace

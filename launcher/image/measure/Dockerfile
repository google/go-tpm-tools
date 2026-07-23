# From current directory:
# gcloud builds submit --tag us-docker.pkg.dev/confidential-space-images-dev/cs-tools/measure:latest --project confidential-space-images-dev

FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY extract_image_ovmf.go ./
RUN go build -o /usr/local/bin/extract_image_ovmf extract_image_ovmf.go

FROM gcr.io/cloud-builders/gcloud

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install all necessary CLI tools
# - cgpt: for GPT partition manipulation
# - mtools: provides 'mcopy' to read FAT partitions
# - sbsigntool: provides 'sbattach' to extract EFI signatures
# - openssl: for hash and certificate processing
RUN apt-get update && apt-get install -y \
    apt-transport-https \
    ca-certificates \
    gnupg \
    curl \
    lsb-release \
    cgpt \
    mtools \
    sbsigntool \
    openssl \
    jq \
    coreutils \
    gawk \
    grep \
    python3-pip \
    qemu-utils \
    e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir lief


# Copy the compiled extract_image_ovmf binary from builder stage
COPY --from=builder /usr/local/bin/extract_image_ovmf /usr/local/bin/extract_image_ovmf

# Copy the measure.sh script into the container
# Ensure you have the script file in the same directory as this Dockerfile
COPY measure_composite.sh /usr/local/bin/measure_composite.sh
RUN chmod +x /usr/local/bin/measure_composite.sh

COPY measure.sh /usr/local/bin/measure.sh
RUN chmod +x /usr/local/bin/measure.sh

# Set the working directory for data processing
WORKDIR /data

# Set the script as the entrypoint
ENTRYPOINT ["/usr/local/bin/measure.sh"]

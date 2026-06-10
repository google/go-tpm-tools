# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/guest-gpu-tools:latest --project confidential-space-images-dev

FROM ubuntu:24.04

# Install dependencies needed for the script and installation
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    infiniband-diags \
    sed \
    grep \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add NVIDIA CUDA repository
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb \
    && dpkg -i cuda-keyring_1.1-1_all.deb \
    && apt-get update

# Install nvidia-driver, fabricmanager, and nvlsm
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nvidia-driver-590-server \
    nvidia-fabricmanager-590 \
    nvlsm \
    && rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

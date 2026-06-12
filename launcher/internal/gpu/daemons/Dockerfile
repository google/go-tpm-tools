FROM ubuntu:24.04

# Install dependencies needed for the script and installation
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    infiniband-diags \
    sed \
    grep \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add NVIDIA CUDA keyring (which configures the repository).
# This GPG keyring is required to verify package signatures and install nvidia-driver and fabricmanager.
# Note: This is NOT the customer workload's CUDA runtime (workload containers package their own CUDA).
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

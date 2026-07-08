# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/guest-gpu-tools:latest --project confidential-space-images-dev

FROM ubuntu:24.04

# Install dependencies needed for the script and installation
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    infiniband-diags \
    sed \
    build-essential \
    grep \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install nvlsm
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/nvlsm_2025.06.10-1_amd64.deb \
    && dpkg -i nvlsm_2025.06.10-1_amd64.deb || DEBIAN_FRONTEND=noninteractive apt-get install -f -y \
    && rm nvlsm_2025.06.10-1_amd64.deb

# Add NVIDIA CUDA repository
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb \
    && dpkg -i cuda-keyring_1.1-1_all.deb

# Install nvidia-driver and fabricmanager from the NVIDIA repository
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nvidia-driver=595.58.03-1ubuntu1 \
        nvidia-dkms=595.58.03-1ubuntu1 \
        xserver-xorg-video-nvidia=595.58.03-1ubuntu1 \
        libnvidia-gl=595.58.03-1ubuntu1 \
        nvidia-kernel-common=595.58.03-1ubuntu1 \
        nvidia-kernel-source=595.58.03-1ubuntu1 \
        libnvidia-compute=595.58.03-1ubuntu1 \
        libnvidia-decode=595.58.03-1ubuntu1 \
        libnvidia-encode=595.58.03-1ubuntu1 \
        libnvidia-fbc1=595.58.03-1ubuntu1 \
        nvidia-fabricmanager=595.58.03-1ubuntu1 \
        libnvidia-cfg1=595.58.03-1ubuntu1 \
        libnvidia-gpucomp=595.58.03-1ubuntu1 \
        nvidia-persistenced=595.58.03-1ubuntu1 \
        nvidia-firmware=595.58.03-1ubuntu1 \
        nvidia-modprobe=595.58.03-1ubuntu1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
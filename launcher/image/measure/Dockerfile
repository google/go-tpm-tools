# From current directory:
# gcloud builds submit --tag us-docker.pkg.dev/confidential-space-images-dev/cs-tools/measure:latest --project confidential-space-images-dev
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
    && rm -rf /var/lib/apt/lists/*

# Copy the measure.sh script into the container
# Ensure you have the script file in the same directory as this Dockerfile
COPY measure.sh /usr/local/bin/measure.sh
RUN chmod +x /usr/local/bin/measure.sh

# Set the working directory for data processing
WORKDIR /data

# Set the script as the entrypoint
ENTRYPOINT ["/usr/local/bin/measure.sh"]

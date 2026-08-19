#!/bin/bash
set -euo pipefail

NVIDIA_BIN_DIR="/opt/nvidia/595.58.03/bin"

echo "modprobe nvidia modules" | tee /dev/console

# Install gpu drivers
modprobe nvidia
modprobe nvidia-uvm
modprobe nvidia-modeset

echo "Running nvidia-persistenced" | tee /dev/console
systemd-run -p Type=forking --unit=nvidia-persistenced-transient /opt/nvidia/595.58.03/bin/nvidia-persistenced

echo "Waiting 1 minute for nvidia-persistenced to initialize..." | tee /dev/console
sleep 60s

echo "run nvidia-modprobe -u -c 0" | tee /dev/console
"${NVIDIA_BIN_DIR}/nvidia-modprobe" -u -c 0

ls -a /dev/*nvidia* | tee /dev/console
echo "run nvidia-smi" | tee /dev/console
"${NVIDIA_BIN_DIR}/nvidia-smi" | tee /dev/console

echo "GPU daemon ready" | tee /dev/console

#!/bin/bash
set -euo pipefail

# Install gpu drivers
modprobe ib_umad
modprobe nvidia
modprobe nvidia-uvm
modprobe nvidia-modeset

echo "Running nvidia-persistenced" | tee /dev/console
systemd-run -p Type=forking --unit=nvidia-persistenced-transient /opt/nvidia/595.58.03/bin/nvidia-persistenced

echo "Waiting 1 minute for nvidia-persistenced to initialize..." | tee /dev/console
sleep 60s



echo "GPU daemon ready" | tee /dev/console

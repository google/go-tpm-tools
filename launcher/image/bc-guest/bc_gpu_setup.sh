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

if [ ! -d /usr/share/oem/gpu_helper/rootfs ]; then
    echo "Error: GPU rootfs not found at /usr/share/oem/gpu_helper/rootfs!" | tee /dev/console
    exit 1
fi

# echo "Running NVLSM and Fabric Manager..." | tee /dev/console

# sudo ctr containers create --rootfs --privileged --net-host \
#     --mount type=bind,src=/dev,dst=/dev,options=rbind:rw \
#     --mount type=bind,src=/opt/nvidia,dst=/opt/nvidia-host,options=rbind:rw \
#     /usr/share/oem/gpu_helper/rootfs \
#     guest-gpu-tools-task \
#     /entrypoint.sh

# sudo ctr tasks start -d guest-gpu-tools-task
# echo "Waiting 2 min for NVLSM and Fabric Manager to initialize..." | tee /dev/console
# sleep 2m

echo "Skipping NVLSM and Fabric Manager" | tee /dev/console

echo "GPU daemon ready" | tee /dev/console

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

if [ -f  /usr/share/oem/confidential_space/gpu_helper.tar ]; then
    echo "Importing GPU helper image..." | tee /dev/console
    sudo ctr images import /usr/share/oem/confidential_space/gpu_helper.tar
fi

echo "Running NVLSM and Fabric Manager..." | tee /dev/console

sudo ctr containers create --privileged --net-host \
    --mount type=bind,src=/dev,dst=/dev,options=rbind:rw \
    --mount type=bind,src=/opt/nvidia,dst=/opt/nvidia-host,options=rbind:rw \
    docker.io/library/guest-gpu-tools:latest \
    guest-gpu-tools-task

sudo ctr tasks start -d guest-gpu-tools-task
echo "Waiting 2 min for NVLSM and Fabric Manager to initialize..." | tee /dev/console
sleep 2m

echo "GPU daemon ready" | tee /dev/console

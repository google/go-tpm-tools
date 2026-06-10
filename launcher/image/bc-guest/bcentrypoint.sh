#!/bin/bash

main() {
  # Configure sysctls.
  sysctl -w kernel.kexec_load_disabled=1

  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  cp /usr/share/oem/wsd/wsd.service /etc/systemd/system/wsd.service
  # Override default fluent-bit config.
  mkdir -p /etc/fluent-bit
  cp /usr/share/oem/confidential_space/fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf

  mkdir /tmp/container_launcher
  chmod +rw /tmp/container_launcher
  cp /usr/share/oem/confidential_space/bcexperiment.json /tmp/container_launcher/experiment_data

  # Override default system-stats-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/nodeproblemdetector/system-stats-monitor-cs.json /etc/node_problem_detector/system-stats-monitor.json
  # Override default boot-disk-size-consistency-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/nodeproblemdetector/boot-disk-size-consistency-monitor-cs.json /etc/node_problem_detector/boot-disk-size-consistency-monitor.json
  # Override default docker-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/nodeproblemdetector/docker-monitor-cs.json /etc/node_problem_detector/docker-monitor.json
  # Override default kernel-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/nodeproblemdetector/kernel-monitor-cs.json /etc/node_problem_detector/kernel-monitor.json

  # Configure network priority for IDPF using systemd-networkd.
  if [[ -f /usr/share/oem/confidential_space/bc_network_setup.sh ]]; then
    /usr/share/oem/confidential_space/bc_network_setup.sh
  fi

  # Wait for containerd socket to be ready
  echo "Waiting for containerd socket..."
  while [[ ! -S "/run/containerd/containerd.sock" ]]; do
    sleep 1
  done

  # Detect if NVIDIA GPU is present on the host PCI bus
  if grep -q "0x10de" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
    echo "NVIDIA GPU detected, running GPU setup..."
    if ! setup_gpu; then
      echo "Fatal: GPU setup failed!"
      exit 1
    fi
  else
    echo "No NVIDIA GPU detected, skipping GPU setup."
  fi

  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl enable wsd.service
  systemctl start container-runner.service
  systemctl start wsd.service
  systemctl start fluent-bit.service
}

setup_gpu() {
  echo "Setting up GPU host requirements..."
  
  # 1. Create host directories for communication
  mkdir -p /run/nvidia
  mkdir -p /var/run/nvidia-fabricmanager

  # 2. Load ib_umad module
  echo "Loading ib_umad module..."
  modprobe ib_umad || echo "Failed to load ib_umad"

  # 3. Load nvidia kernel modules with GSP firmware offload.
  # GSP (GPU System Processor) offloading is mandatory for Hopper (H100) and Blackwell (B200)
  # GPUs in Confidential Computing. It establishes secure CPU-GPU channels and attestation,
  # while minimizing guest-host MMIO context switch overhead.
  # NOTE: Without NVreg_EnableGpuFirmware=1, the NVIDIA kernel module crashes during memory mapping
  # (RmInitAdapter fails with 'assertion failed: pVGpu != NULL @ objvgpu.c:148' and 'Disabling GSP offload'),
  # dropping all GPUs and causing nvidia-smi to report "No devices were found".
  echo "Loading nvidia modules..."
  modprobe nvidia NVreg_EnableGpuFirmware=1 || {
    echo "Error: Failed to load nvidia kernel module"
    return 1
  }
  modprobe nvidia-uvm || {
    echo "Error: Failed to load nvidia-uvm kernel module"
    return 1
  }
  modprobe nvidia-modeset || {
    echo "Error: Failed to load nvidia-modeset kernel module"
    return 1
  }

  # Load nvidia-peermem if RDMA is present.
  # nvidia-peermem enables GPUDirect RDMA, allowing direct GPU-to-GPU data paths over high-speed networks 
  # (InfiniBand/RoCE), bypassing CPU memory. We only load it if RDMA hardware (/sys/class/infiniband) is 
  # detected; otherwise, loading it will fail with "Invalid argument" due to missing kernel symbol links.
  if ls /sys/class/infiniband &>/dev/null && [ "$(ls -A /sys/class/infiniband)" ]; then
    echo "RDMA detected, loading nvidia-peermem..."
    modprobe nvidia-peermem || echo "Failed to load nvidia-peermem"
  fi

  # 4. Start host daemons (persistenced, modprobe device node creation)
  local persistenced_cmd=""
  if [[ -f "/var/lib/nvidia/bin/nvidia-persistenced" ]]; then
    persistenced_cmd="/var/lib/nvidia/bin/nvidia-persistenced"
  else
    for d in /opt/nvidia/*; do
      if [[ -d "$d" && -f "$d/bin/nvidia-persistenced" ]]; then
        persistenced_cmd="$d/bin/nvidia-persistenced"
        break
      fi
    done
  fi

  if [[ -n "$persistenced_cmd" ]]; then
    echo "Starting nvidia-persistenced: $persistenced_cmd"
    "$persistenced_cmd" || echo "Failed to start nvidia-persistenced"
  else
    echo "nvidia-persistenced not found on host"
  fi

  # Trigger character devices creation
  local modprobe_cmd=""
  if [[ -f "/var/lib/nvidia/bin/nvidia-modprobe" ]]; then
    modprobe_cmd="/var/lib/nvidia/bin/nvidia-modprobe"
  else
    for d in /opt/nvidia/*; do
      if [[ -d "$d" && -f "$d/bin/nvidia-modprobe" ]]; then
        modprobe_cmd="$d/bin/nvidia-modprobe"
        break
      fi
    done
  fi

  if [[ -n "$modprobe_cmd" ]]; then
    echo "Triggering character devices creation with: $modprobe_cmd"
    "$modprobe_cmd" -c 0 -u || echo "Failed to run nvidia-modprobe"
  else
    echo "nvidia-modprobe not found on host"
  fi

  # Verify GPU state
  local smi_cmd=""
  if [[ -f "/var/lib/nvidia/bin/nvidia-smi" ]]; then
    smi_cmd="/var/lib/nvidia/bin/nvidia-smi"
  else
    for d in /opt/nvidia/*; do
      if [[ -d "$d" && -f "$d/bin/nvidia-smi" ]]; then
        smi_cmd="$d/bin/nvidia-smi"
        break
      fi
    done
  fi

  if [[ -n "$smi_cmd" ]]; then
    echo "Verifying hardware state with: $smi_cmd"
    "$smi_cmd" || echo "Failed to run nvidia-smi"
  fi

  # 5. Import the sidecar image into containerd
  local tar_path=""
  local paths=(
    "/usr/share/oem/gpu_daemons/image.tar"
    "/usr/share/oem/image.tar"
  )
  for p in "${paths[@]}"; do
    if [[ -f "$p" ]]; then
      tar_path="$p"
      break
    fi
  done

  if [[ -z "$tar_path" ]]; then
    echo "Error: guest GPU tools image.tar not found"
    return 1
  fi

  echo "Importing guest GPU tools image from $tar_path..."
  ctr -n default images import "$tar_path" || {
    echo "Error: failed to import guest GPU tools image"
    return 1
  }

  # Clean up any existing sidecar container
  if ctr -n default containers list -q | grep -q "^guest-gpu-tools-container$"; then
    echo "Deleting existing guest-gpu-tools-container..."
    ctr -n default tasks kill -s SIGKILL guest-gpu-tools-container &>/dev/null || true
    ctr -n default tasks delete guest-gpu-tools-container &>/dev/null || true
    ctr -n default containers delete guest-gpu-tools-container || true
  fi

  # Determine host driver directory to mount
  local host_driver_dir="/var/lib/nvidia"
  if [[ -d "/opt/nvidia" ]]; then
    host_driver_dir="/opt/nvidia"
  fi
  echo "Using host GPU driver directory for mounts: $host_driver_dir"

  # 6. Run sidecar container using ctr
  echo "Starting guest GPU tools sidecar container..."
  ctr -n default run \
    --privileged \
    --net-host \
    --detach \
    --mount type=bind,src=/dev,dst=/dev,options=rbind:rw \
    --mount type=bind,src=/run/nvidia,dst=/run/nvidia,options=rbind:rw \
    --mount type=bind,src=/var/run/nvidia-fabricmanager,dst=/var/run/nvidia-fabricmanager,options=rbind:rw \
    --mount type=bind,src="$host_driver_dir",dst=/opt/nvidia-host,options=rbind:rw \
    docker.io/library/guest-gpu-tools:latest \
    guest-gpu-tools-container || {
      echo "Error: failed to start guest GPU tools container"
      return 1
    }

  # 7. Wait for ready state (max 2 minutes)
  echo "Waiting for GPU services to report ready..."
  local timeout=120
  local count=0
  while [[ ! -f "/run/nvidia/gpu-ready" ]]; do
    if (( count >= timeout )); then
      echo "Error: timed out waiting for GPU driver initialization"
      return 1
    fi
    sleep 1
    (( count++ ))
  done

  echo "GPU services successfully initialized!"
  return 0
}

main

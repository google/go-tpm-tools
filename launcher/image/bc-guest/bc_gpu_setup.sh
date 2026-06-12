#!/bin/bash
# Host-level GPU driver and sidecar container setup for BC VMs.

setup_gpu() {
  echo "Setting up GPU host requirements..." > /dev/console
  
  # 1. Create host directories for communication.
  # /run/nvidia is a shared host path where the sidecar container will write the gpu-ready status file once switches are configured.
  mkdir -p /run/nvidia
  mkdir -p /var/run/nvidia-fabricmanager

  # 2. Setup stable /var/lib/nvidia symlink.
  # This links the pre-installed versioned driver directory (/opt/nvidia/590.48.01) to the stable /var/lib/nvidia path.
  # This is required because GPU attestation EnableReadyState() expects the hardcoded path
  # '/var/lib/nvidia/bin/nvidia-smi', and the container runner bind-mounts '/var/lib/nvidia' into the workload.
  if [[ ! -d "/opt/nvidia/590.48.01" ]]; then
    echo "Error: /opt/nvidia/590.48.01 driver directory not found on host" > /dev/console
    return 1
  fi

  mkdir -p /var/lib
  ln -sfn "/opt/nvidia/590.48.01" /var/lib/nvidia
  echo "Created host symlink: /var/lib/nvidia -> /opt/nvidia/590.48.01" > /dev/console

  # 3. Load ib_umad module
  echo "Loading ib_umad module..." > /dev/console
  modprobe ib_umad || echo "Failed to load ib_umad" > /dev/console

  # 4. Load nvidia kernel modules.
  # Verify NVIDIA kernel modules exist on disk before loading
  if [[ ! -d "/lib/modules/$(uname -r)/nvidia" ]] || ! ls /lib/modules/$(uname -r)/nvidia/*/nvidia.ko &>/dev/null; then
    echo "Error: NVIDIA kernel modules not found under /lib/modules/$(uname -r)/nvidia/" > /dev/console
    return 1
  fi

  echo "Loading nvidia modules..." > /dev/console
  modprobe nvidia || {
    echo "Error: Failed to load nvidia kernel module" > /dev/console
    return 1
  }
  modprobe nvidia-uvm || {
    echo "Error: Failed to load nvidia-uvm kernel module" > /dev/console
    return 1
  }
  modprobe nvidia-modeset || {
    echo "Error: Failed to load nvidia-modeset kernel module" > /dev/console
    return 1
  }

  # Load nvidia-peermem if RDMA is present.
  # nvidia-peermem enables GPUDirect RDMA, allowing direct GPU-to-GPU data paths over high-speed networks 
  # (InfiniBand/RoCE), bypassing CPU memory. We only load it if RDMA hardware (/sys/class/infiniband) is 
  # detected; otherwise, loading it will fail with "Invalid argument" due to missing kernel symbol links.
  if ls /sys/class/infiniband &>/dev/null && [ "$(ls -A /sys/class/infiniband)" ]; then
    echo "RDMA detected, loading nvidia-peermem..." > /dev/console
    modprobe nvidia-peermem || {
      echo "Error: Failed to load nvidia-peermem module on RDMA-enabled hardware" > /dev/console
      return 1
    }
  fi

  # 5. Start host daemons using the versioned driver path
  echo "Starting nvidia-persistenced: /opt/nvidia/590.48.01/bin/nvidia-persistenced" > /dev/console
  /opt/nvidia/590.48.01/bin/nvidia-persistenced || {
    echo "Error: Failed to start nvidia-persistenced daemon" > /dev/console
    return 1
  }

  echo "Triggering character devices creation: /opt/nvidia/590.48.01/bin/nvidia-modprobe -c 0 -u" > /dev/console
  /opt/nvidia/590.48.01/bin/nvidia-modprobe -c 0 -u || {
    echo "Error: Failed to run nvidia-modprobe" > /dev/console
    return 1
  }

  # 6. Verify GPU hardware state
  echo "Verifying hardware state with: /opt/nvidia/590.48.01/bin/nvidia-smi" > /dev/console
  if ! /opt/nvidia/590.48.01/bin/nvidia-smi; then
    echo "Error: GPU hardware verification failed! nvidia-smi could not communicate with the driver." > /dev/console
    return 1
  fi

  # 7. Import the sidecar image into containerd
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
    echo "Error: guest GPU tools image.tar not found" > /dev/console
    return 1
  fi

  echo "Importing guest GPU tools image from $tar_path..." > /dev/console
  ctr -n default images import "$tar_path" || {
    echo "Error: failed to import guest GPU tools image" > /dev/console
    return 1
  }

  # Clean up any existing sidecar container
  if ctr -n default containers list -q | grep -q "^guest-gpu-tools-container$"; then
    echo "Deleting existing guest-gpu-tools-container..." > /dev/console
    ctr -n default tasks kill -s SIGKILL guest-gpu-tools-container &>/dev/null || true
    ctr -n default tasks delete guest-gpu-tools-container &>/dev/null || true
    ctr -n default containers delete guest-gpu-tools-container || true
  fi

  # 8. Run sidecar container using ctr.
  # Note: The fully-qualified reference 'docker.io/library/guest-gpu-tools:latest' is required
  # because ctr does not support registry/library implicit defaults like Docker does. This is a
  # local execution; containerd does not make a network request since we imported it in step 7.
  # Note: The sidecar's internal entrypoint.sh automatically configures the symmetric rail policy
  # and launches the Fabric Manager / NVSwitches daemons.
  echo "Starting guest GPU tools sidecar container..." > /dev/console
  ctr -n default run \
    --privileged \
    --net-host \
    --detach \
    --mount type=bind,src=/dev,dst=/dev,options=rbind:rw \
    --mount type=bind,src=/run/nvidia,dst=/run/nvidia,options=rbind:rw \
    --mount type=bind,src=/var/run/nvidia-fabricmanager,dst=/var/run/nvidia-fabricmanager,options=rbind:rw \
    --mount type=bind,src="/opt/nvidia/590.48.01",dst=/opt/nvidia-host,options=rbind:rw \
    docker.io/library/guest-gpu-tools:latest \
    guest-gpu-tools-container || {
      echo "Error: failed to start guest GPU tools container" > /dev/console
      return 1
    }

  # 9. Wait for ready state (max 2 minutes).
  # The '/run/nvidia/gpu-ready' marker file is written by the GPU daemon sidecar container
  # (guest-gpu-tools) once it completes NVSwitch link configuration and driver setup.
  # This loop prevents the host script from exiting (and systemd from starting the Go launcher)
  # until the GPU hardware fabrics are fully initialized and ready to accept compute workloads.
  echo "Waiting for GPU services to report ready..." > /dev/console
  local timeout=120
  local count=0
  while [[ ! -f "/run/nvidia/gpu-ready" ]]; do
    if (( count >= timeout )); then
      echo "Error: timed out waiting for GPU driver initialization" > /dev/console
      return 1
    fi
    # Verify the sidecar container task is still running; fail early if the daemon crashed
    if ! ctr -n default tasks list -q | grep -q "^guest-gpu-tools-container$"; then
      echo "Error: guest-gpu-tools-container task exited prematurely" > /dev/console
      return 1
    fi
    sleep 1
    (( count++ ))
  done

  echo "GPU services successfully initialized!" > /dev/console
  return 0
}

main() {
  # Wait for containerd socket to be ready (timeout 60 seconds)
  echo "Waiting for containerd socket..." > /dev/console
  local count=0
  while [[ ! -S "/run/containerd/containerd.sock" ]]; do
    if (( count >= 60 )); then
      echo "Error: timed out waiting for containerd socket to become ready" > /dev/console
      exit 1
    fi
    sleep 1
    (( count++ ))
  done

  # Detect if NVIDIA GPU is present on the host PCI bus
  if grep -q "0x10de" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
    echo "NVIDIA GPU detected, running GPU setup..." > /dev/console
    if ! setup_gpu; then
      echo "Fatal: GPU setup failed!" > /dev/console
      exit 1
    fi
  else
    echo "No NVIDIA GPU detected, skipping GPU setup." > /dev/console
  fi
}

main "$@"

#!/bin/bash
# Description: Host-level GPU driver and sidecar container setup for Bowcaster VMs.

setup_gpu() {
  echo "Setting up GPU host requirements..."
  
  # 1. Create host directories for communication.
  # /run/nvidia is a shared host path where the sidecar container will write the gpu-ready status file once switches are configured.
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
  # Note: modprobe automatically resolves and loads core dependencies like i2c_core and drm
  # (unlike insmod, which would require loading them manually).
  
  # Configure modprobe options to ensure GSP firmware offload is enabled system-wide.
  # This is critical because the kernel/udev may auto-load the 'nvidia' module during early boot
  # before this setup script is executed. If it auto-loads, it loads with default settings (GSP disabled),
  # which causes physical memory mapping to fail. Writing to modprobe.d ensures any subsequent loading
  # (automatic or manual) inherits this option.
  mkdir -p /etc/modprobe.d
  echo "options nvidia NVreg_EnableGpuFirmware=1" > /etc/modprobe.d/nvidia.conf

  # If the nvidia module was already loaded by the kernel/udev during boot (without GSP settings),
  # we must unload it (and its dependent modules) and reload it cleanly so the modprobe.d rule takes effect.
  if lsmod | grep -q "^nvidia "; then
    echo "Nvidia module already loaded. Unloading to apply correct GSP settings..."
    modprobe -r nvidia-modeset || true
    modprobe -r nvidia-uvm || true
    modprobe -r nvidia || rmmod -f nvidia || echo "Failed to unload nvidia module"
  fi

  echo "Loading nvidia modules..."
  modprobe nvidia || {
    echo "Error: Failed to load nvidia kernel module"
    return 1
  }

  # Verify GSP firmware is active in the loaded driver before loading dependent modules
  if ! grep -q "EnableGpuFirmware: 1" /proc/driver/nvidia/params; then
    echo "Error: NVIDIA module loaded, but EnableGpuFirmware is NOT enabled."
    return 1
  fi
  echo "Verified GSP firmware offload parameter is active."
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
    modprobe nvidia-peermem || {
      echo "Error: Failed to load nvidia-peermem module on RDMA-enabled hardware"
      return 1
    }
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
    "$persistenced_cmd" || {
      echo "Error: Failed to start nvidia-persistenced daemon"
      return 1
    }
  else
    echo "Error: nvidia-persistenced not found on host"
    return 1
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
    "$modprobe_cmd" -c 0 -u || {
      echo "Error: Failed to run nvidia-modprobe"
      return 1
    }
  else
    echo "Error: nvidia-modprobe not found on host"
    return 1
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
    if ! "$smi_cmd"; then
      echo "Error: GPU hardware verification failed! nvidia-smi could not communicate with the driver."
      return 1
    fi
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
  local symlink_created=false
  if [[ -d "/opt/nvidia" ]]; then
    host_driver_dir="/opt/nvidia"
    # Create a symbolic link from /var/lib/nvidia to the versioned driver directory (e.g., /opt/nvidia/590.48.01).
    # This is required because the Go launcher's EnableReadyState() function has a hardcoded path that expects
    # nvidia-smi at '/var/lib/nvidia/bin/nvidia-smi' to promote the GPU enclaves to READY state (-srs 1)
    # after attestation measurements are taken.
    for d in /opt/nvidia/*; do
      if [[ -d "$d" ]]; then
        mkdir -p /var/lib
        ln -sfn "$d" /var/lib/nvidia
        echo "Created host symlink: /var/lib/nvidia -> $d"
        symlink_created=true
        break
      fi
    done
    if [[ "$symlink_created" != "true" ]]; then
      echo "Error: /opt/nvidia is empty or does not contain driver directories"
      return 1
    fi
  fi
  echo "Using host GPU driver directory for mounts: $host_driver_dir"

  # 6. Run sidecar container using ctr.
  # Note: The fully-qualified reference 'docker.io/library/guest-gpu-tools:latest' is required
  # because ctr does not support registry/library implicit defaults like Docker does. This is a
  # local execution; containerd does not make a network request since we imported it in step 5.
  # Note: The sidecar's internal entrypoint.sh automatically configures the symmetric rail policy
  # and launches the Fabric Manager / NVSwitches daemons.
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

  # 7. Wait for ready state (max 2 minutes).
  # The '/run/nvidia/gpu-ready' marker file is written by the GPU daemon sidecar container
  # (guest-gpu-tools) once it completes NVSwitch link configuration and driver setup.
  # This loop prevents the host script from exiting (and systemd from starting the Go launcher)
  # until the GPU hardware fabrics are fully initialized and ready to accept compute workloads.
  echo "Waiting for GPU services to report ready..."
  local timeout=120
  local count=0
  while [[ ! -f "/run/nvidia/gpu-ready" ]]; do
    if (( count >= timeout )); then
      echo "Error: timed out waiting for GPU driver initialization"
      return 1
    fi
    # Verify the sidecar container task is still running; fail early if the daemon crashed
    if ! ctr -n default tasks list -q | grep -q "^guest-gpu-tools-container$"; then
      echo "Error: guest-gpu-tools-container task exited prematurely"
      return 1
    fi
    sleep 1
    (( count++ ))
  done

  echo "GPU services successfully initialized!"
  return 0
}

main() {
  # Wait for containerd socket to be ready (timeout 60 seconds)
  echo "Waiting for containerd socket..."
  local count=0
  while [[ ! -S "/run/containerd/containerd.sock" ]]; do
    if (( count >= 60 )); then
      echo "Error: timed out waiting for containerd socket to become ready"
      exit 1
    fi
    sleep 1
    (( count++ ))
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
}

main "$@"

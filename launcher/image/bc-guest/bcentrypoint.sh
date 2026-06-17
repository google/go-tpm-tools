#!/bin/bash

main() {
  # Set IMA policy
  if [[ -f /usr/share/oem/ima-policy ]]; then
    cp /usr/share/oem/ima-policy /sys/kernel/security/ima/policy
  fi

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

  systemctl daemon-reload

  # Install gpu drivers
  modprobe ib_umad
  modprobe nvidia
  modprobe nvidia-uvm
  modprobe nvidia-modeset

  echo "Running nvidia-persistenced" | tee /dev/console
  systemd-run  -p Type=forking --unit=nvidia-persistenced-transient /opt/nvidia/590.48.01/bin/nvidia-persistenced

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

  systemctl enable container-runner.service
  systemctl enable wsd.service
  systemctl start container-runner.service
  systemctl start wsd.service
  systemctl start fluent-bit.service
}

main

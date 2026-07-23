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
  cp /usr/share/oem/confidential_space/bc-fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf

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

  # Bind-mount /bin/true over the google_set_multiqueue to disable it and prevent random resets to the network configuration.
  if [[ -f /usr/bin/google_set_multiqueue ]]; then
    echo "Disabling /usr/bin/google_set_multiqueue via bind mount" > /dev/console
    mount --bind /bin/true /usr/bin/google_set_multiqueue || true
  fi

  # Configure GPU, NIC, and Bridge NUMA nodes and rebind drivers.
  if [[ -f /usr/share/oem/confidential_space/bc_pin_pci_numa_nodes.sh ]]; then
    /usr/share/oem/confidential_space/bc_pin_pci_numa_nodes.sh
  fi

  # Configure network priority for IDPF using systemd-networkd.
  if [[ -f /usr/share/oem/confidential_space/bc_network_setup.sh ]]; then
    /usr/share/oem/confidential_space/bc_network_setup.sh
  fi

  systemctl daemon-reload

  # Install gpu drivers
  if [[ -f /usr/share/oem/confidential_space/bc_gpu_setup.sh ]]; then
    /usr/share/oem/confidential_space/bc_gpu_setup.sh
  fi

  # Allow incoming Fluent Bit logs from KPS VM
  iptables -A INPUT -p tcp -s 192.168.100.3 --dport 24224 -j ACCEPT

  systemctl enable container-runner.service
  systemctl enable wsd.service
  systemctl start container-runner.service
  systemctl start wsd.service
  systemctl start fluent-bit.service
}

main

#!/bin/bash

main() {
  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  # Setup CNI config
  mkdir -p /etc/cni/net.d
  cp /usr/share/oem/confidential_space/10-workload.conf /etc/cni/net.d/10-workload.conf
  # Override default fluent-bit config.
  cp /usr/share/oem/confidential_space/fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf

  # Override default system-stats-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/system-stats-monitor-cs.json /etc/node_problem_detector/system-stats-monitor.json
  # Override default boot-disk-size-consistency-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/boot-disk-size-consistency-monitor-cs.json /etc/node_problem_detector/boot-disk-size-consistency-monitor.json
  # Override default docker-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/docker-monitor-cs.json /etc/node_problem_detector/docker-monitor.json
  # Override default kernel-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/kernel-monitor-cs.json /etc/node_problem_detector/kernel-monitor.json
  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
  systemctl start fluent-bit.service
}

main

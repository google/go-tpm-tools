#!/bin/bash

main() {
  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  # Override default fluent-bit config.
  cp /usr/share/oem/confidential_space/fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf

  # Override default system-stats-monitor.json for node-problem-detector.
  cp /usr/share/oem/confidential_space/system-stats-monitor-cs.json /etc/node_problem_detector/system-stats-monitor.json
  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
  systemctl start fluent-bit.service

}

main

#!/bin/bash

main() {
  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  # Override default fluent-bit config.
  cp /usr/share/oem/confidential_space/fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf
  # Deprive logind of its power button handling capability for debug images.
  if [[ "$(systemctl show -p LoadState systemd-logind.service 2>/dev/null)" == "LoadState=loaded" ]]; then
    mkdir -p /etc/systemd/logind.conf.d
    cp /usr/share/oem/confidential_space/logind_override.conf /etc/systemd/logind.conf.d/logind_override.conf
    systemctl restart systemd-logind.service
  fi

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

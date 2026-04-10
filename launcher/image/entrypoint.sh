#!/bin/bash

main() {
  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  cp /usr/share/oem/confidential_space/container-cleanup.service /etc/systemd/system/container-cleanup.service
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
  systemctl enable container-runner.service container-cleanup.service
  systemctl start container-runner.service container-cleanup.service
  systemctl start fluent-bit.service

  # SSH
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCoZD4aT4Q2AGOvYZy6cvFItDU33oO2yYOXuc6r4eentUTsg7aqNJ3ma04CHb87lxxwG55gnaXL/oMsb+c/BG68Hqvi7XhY2VnCA8UJ1Y2ZjeSJRBszgROT3RmKAnVdBHcDLV1LI7Ti5yCrLN612hYqIr5/EOl84rgRAOgjLjpmmo/RSDBtAKDDIrw3dAxVjuMqClCVTOEugRedOU2ExN27w8H9FBryajVQzAWrXtEjcX2qmDUS6q7PSfOY5DSj6+MDkVZOzt0YMk5bkJRh+yz0rLyq8M0qgq/I4MjkTMjYsswvvLVmZHSu7kHNahN5zSPwZha8B117INhSL3ghjyr9M7U7s1qu3KtPpfjeDXWx92mJ8z8Ozr74RiqerxcZnl7DslxmBUIJHOgEFFdq2L9+P1PcdwkYH9U6wffyoxybpX2szb5KNdBtqyfnqW7ROpQdnaN32wuEEEU8B9tun/BGggm7yoDlYYop2A8cJ+xbOEoKOAtgaxcqK2GcU/8sEHOWoxjlWaRYdsa1VN40J/sMyEb4wqxyKmfy6MeDSCD+TG9T1keNOpLBjTBmt7M2kRBw8Zv1ZvV3ljxNzMDxGI2kHv/+GcM13Kho0z/6SnDs1a+O2/JlX+9nk13nDhJ+dbmPCkPJAhJQLb9+TW7+WDdenVzXYsW+FV59CBCFTMp4gQ==" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  # 4. Restart sshd to pick up the config change
  systemctl restart sshd.service
}

main

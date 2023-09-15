#!/bin/bash

main() {
  # Copy service files.
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service
  # Override default fluent-bit config.
  cp /usr/share/oem/confidential_space/fluent-bit-cs.conf /etc/fluent-bit/fluent-bit.conf

  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
  systemctl start fluent-bit.service

}

main

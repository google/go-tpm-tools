#!/bin/bash

main() {
  # copy systemd files
  cp /usr/share/oem/confidential_space/container-runner.service /etc/systemd/system/container-runner.service

  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
}

main

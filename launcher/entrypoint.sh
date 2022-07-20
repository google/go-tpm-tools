#!/bin/bash

main() {
  # copy the binary
  cp /usr/share/oem/cc_container_launcher /var/lib/google/cc_container_launcher
  chmod +x /var/lib/google/cc_container_launcher
  
  # copy systemd files
  cp /usr/share/oem/container-runner.service /etc/systemd/system/container-runner.service
  mkdir -p /etc/systemd/system/container-runner.service.d/
  cp /usr/share/oem/launcher.conf /etc/systemd/system/container-runner.service.d/launcher.conf

  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
}

main

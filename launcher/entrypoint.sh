#!/bin/bash

main() {
  # copy the binary
  cp /usr/share/oem/cc_container_launcher /var/lib/google/cc_container_launcher
  chmod +x /var/lib/google/cc_container_launcher
  
  cp /usr/share/oem/container-runner.service /etc/systemd/system/container-runner.service
  systemctl daemon-reload
  systemctl enable container-runner.service
  systemctl start container-runner.service
}

main

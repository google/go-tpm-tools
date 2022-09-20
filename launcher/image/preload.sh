#!/bin/bash

copy_launcher() {
  cp launcher /usr/share/oem/cc_container_launcher
}

setup_launcher_systemd_unit() {
  cp container-runner.service /usr/share/oem/container-runner.service

  if [ "$IMAGE_ENV" == "hardened" ]; then
    cp hardened.conf /usr/share/oem/launcher.conf
  elif [ "$IMAGE_ENV" == "debug" ]; then
    cp debug.conf /usr/share/oem/launcher.conf
  else
    echo "Unknown IMAGE_ENV: ${IMAGE_ENV}. Use hardened or debug"
    exit 1
  fi
}

append_cmdline() {
  local arg="$1"
  if [[ ! -d /mnt/disks/efi ]]; then
    mkdir /mnt/disks/efi
  fi
  mount /dev/sda12 /mnt/disks/efi
  sed -i -e "s|cros_efi|cros_efi ${arg}|g" /mnt/disks/efi/efi/boot/grub.cfg
  umount /mnt/disks/efi
}

set_default_boot_target() {
  append_cmdline "systemd.unit=$1"
}

disable_unit() {
  append_cmdline "systemd.mask=$1"
}

enable_unit() {
  append_cmdline "systemd.wants=$1"
}

configure_entrypoint() {
  cp "$1" /usr/share/oem/user-data
  touch /usr/share/oem/meta-data
  append_cmdline "'ds=nocloud;s=/usr/share/oem/'"
}

configure_necessary_systemd_units() {
  # Include basic services.
  enable_unit "basic.target"

  # gcr-wait-online.service is WantedBy=gcr-online.target.
  # The hostname gcr.io does not resolve until systemd-resolved is enabled.
  enable_unit "systemd-resolved.service"

  # Dependencies of container-runner.service.
  enable_unit "network-online.target"
  enable_unit "gcr-online.target"
}

configure_systemd_units_for_debug() {
  # No-op for now, as debug will default to using multi-user.target.
  :
}

configure_systemd_units_for_hardened() {
  configure_necessary_systemd_units
  # Make entrypoint (via cloud-init) the default unit.
  set_default_boot_target "cloud-final.service"

  disable_unit "var-lib-docker.mount"
  disable_unit "docker.service"
  disable_unit "google-guest-agent.service"
  disable_unit "google-osconfig-init.service"
  disable_unit "google-osconfig-agent.service"
  disable_unit "google-startup-scripts.service"
  disable_unit "google-shutdown-scripts.service"
  disable_unit "konlet-startup.service"
  disable_unit "sshd.service"
  disable_unit "var-lib-toolbox.mount"
}

main() {
  mount -o remount,rw /usr/share/oem

  # Install container launcher entrypoint.
  configure_entrypoint "entrypoint.sh"
  # Install container launcher.
  copy_launcher
  setup_launcher_systemd_unit

  if [[ "${IMAGE_ENV}" == "debug" ]]; then
    configure_systemd_units_for_debug
    append_cmdline "'confidential-space.hardened=false'"
  elif [[ "${IMAGE_ENV}" == "hardened" ]]; then
    configure_systemd_units_for_hardened
    append_cmdline "'confidential-space.hardened=true'"
  else
    echo "Unknown image env: ${IMAGE_ENV}." \
         "Only 'debug' and 'hardened' are supported."
    exit 1
  fi
}

main

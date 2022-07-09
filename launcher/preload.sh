#!/bin/bash

copy_launcher() {
  cp launcher/launcher /usr/share/oem/cc_container_launcher
}

setup_launcher_systemd_unit() {
  cp launcher/container-runner.service /usr/share/oem/container-runner.service
  # set attest service endpoint

  if [ "$IMAGE_ENV" == "hardened" ]; then
    cp launcher/hardened.conf /usr/share/oem/launcher.conf
  elif [ "$IMAGE_ENV" == "debug" ]; then
    cp launcher/debug.conf /usr/share/oem/launcher.conf
  else
    echo "Unknown IMAGE_ENV, use hardened or debug"
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

configure_entrypoint() {
  cp "$1" /usr/share/oem/user-data
  touch /usr/share/oem/meta-data
  append_cmdline "'ds=nocloud;s=/usr/share/oem/'"
}

main() {
  mount -o remount,rw /usr/share/oem
  configure_entrypoint "launcher/entrypoint.sh"
  copy_launcher
  setup_launcher_systemd_unit
}

main

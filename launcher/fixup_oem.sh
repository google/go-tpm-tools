#!/bin/bash

main() {
  if [[ ! -d /mnt/disks/efi ]]; then
    mkdir /mnt/disks/efi
  fi
  mount /dev/sda12 /mnt/disks/efi
  sed -i -e 's|systemd.mask=usr-share-oem.mount||g' /mnt/disks/efi/efi/boot/grub.cfg
  umount /mnt/disks/efi
}

main

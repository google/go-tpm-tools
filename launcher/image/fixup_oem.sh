#!/bin/bash

main() {
  if [[ ! -d /mnt/disks/efi ]]; then
    mkdir /mnt/disks/efi
  fi
  mount /dev/sda12 /mnt/disks/efi
  sed -i -e 's|systemd.mask=usr-share-oem.mount||g' /mnt/disks/efi/efi/boot/grub.cfg

  # TODO: Remove this fix once the upstream customizer fixed the bug.
  # Fix a string manipulation bug in the dm part of the kernel cmd.
  if grep -q "dm-m2d" /mnt/disks/efi/efi/boot/grub.cfg; then
    sed -i -e 's|dm-m2d|dm-mod|g' /mnt/disks/efi/efi/boot/grub.cfg
    sed -i -e 's|,oemroot|;oemroot|g' /mnt/disks/efi/efi/boot/grub.cfg
  fi

  # Print grub.cfg's kernel command line.
  grep -i '^\s*linux' /mnt/disks/efi/efi/boot/grub.cfg | \
    sed -e 's|.*|[BEGIN_CS_GRUB_CMDLINE]&[END_CS_GRUB_CMDLINE]|g'

  # Convert grub.cfg's kernel command line into what GRUB passes to the kernel.
  grep -i '^\s*linux' /mnt/disks/efi/efi/boot/grub.cfg | \
    sed -e "s|'ds=nocloud;s=/usr/share/oem/'|ds=nocloud;s=/usr/share/oem/|g" | \
    sed -e 's|\\"|"|g' | \
    sed -e 's|dm-mod.create="|"dm-mod.create=|g' | \
    sed -e 's|.*|[BEGIN_CS_CMDLINE]&[END_CS_CMDLINE]|g'

  umount /mnt/disks/efi
}

main

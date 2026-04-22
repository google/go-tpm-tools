#!/bin/bash

readonly EFI_PARTITION="${EFI_PARTITION:-/dev/sda12}"
readonly OEM_PARTITION="${OEM_PARTITION:-/dev/sda8}"
readonly EFI_MOUNT_PATH="/mnt/disks/efi"
readonly OEM_MOUNT_PATH="/mnt/disks/oem"

main() {
  mkdir -p ${EFI_MOUNT_PATH}
  mount ${EFI_PARTITION} ${EFI_MOUNT_PATH}
  sed -i -e 's|systemd.mask=usr-share-oem.mount||g' ${EFI_MOUNT_PATH}/efi/boot/grub.cfg

  # TODO: Remove this fix once the upstream customizer fixed the bug.
  # Fix a string manipulation bug in the dm part of the kernel cmd.
  if grep -q "dm-m2d" ${EFI_MOUNT_PATH}/efi/boot/grub.cfg; then
    sed -i -e 's|dm-m2d|dm-mod|g' ${EFI_MOUNT_PATH}/efi/boot/grub.cfg
    sed -i -e 's|,oemroot|;oemroot|g' ${EFI_MOUNT_PATH}/efi/boot/grub.cfg
  fi

  # Print grub.cfg's kernel command line.
  grep -i '^\s*linux' ${EFI_MOUNT_PATH}/efi/boot/grub.cfg | \
    sed -e 's|.*|[BEGIN_CS_GRUB_CMDLINE]&[END_CS_GRUB_CMDLINE]|g'

  # Convert grub.cfg's kernel command line into what GRUB passes to the kernel.
  grep -i '^\s*linux' ${EFI_MOUNT_PATH}/efi/boot/grub.cfg | \
    sed -e "s|'ds=nocloud;s=/usr/share/oem/'|ds=nocloud;s=/usr/share/oem/|g" | \
    sed -e 's|\\"|"|g' | \
    sed -e 's|dm-mod.create="|"dm-mod.create=|g' | \
    sed -e 's|.*|[BEGIN_CS_CMDLINE]&[END_CS_CMDLINE]|g'

  umount ${EFI_MOUNT_PATH}

  # Now the oem partition is sealed, we mount it to print it's content
  mkdir -p ${OEM_MOUNT_PATH}

  # Since it's sealed, we mount it read-only to prevent changes
  mount -o ro ${OEM_PARTITION} ${OEM_MOUNT_PATH}

  ls -l ${OEM_MOUNT_PATH}/
  ls -l ${OEM_MOUNT_PATH}/confidential_space

  umount ${OEM_MOUNT_PATH}
}

main

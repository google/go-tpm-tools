#!/usr/bin/ash

unlocked=0
# Loop through all devices to find the ESP
for device in $(blkid -o device); do
    part_type=$(blkid -p $device -s PART_ENTRY_TYPE -o value)
    if [ "$part_type" != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ]; then
        continue
    fi

    # Temporarily mount the ESP to read disk unlock keys
    mkdir -p /mnt/esp
    mount -t vfat $device /mnt/esp

    # Try all of the keys in the appropriate folder
    for f in /mnt/esp/*/disk_unlock_keys/*.sealed; do
        if gotpm unseal --input "$f" --output "/crypto_keyfile.bin" ; then
            echo "gotpm: Unsealed $f"
            unlocked=1
            break
        fi
    done
    umount $device

    if [ $unlocked -ne 0 ]; then
        break
    fi
done

if [ $unlocked -eq 0 ]; then
    echo "gotpm: Unable to unseal TPM disk unlock key"
fi

# vim: set ft=sh ts=4 sw=4 et:

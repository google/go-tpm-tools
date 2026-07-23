#!/bin/bash

# Exit on error
set -e

mount_overlay() {
    local target="$1"
    local upper
    local work
    if [[ -d "${target}" ]]; then
        upper=$(mktemp -d)
        work=$(mktemp -d)
        mount -t overlay -o "rw,noexec,nosuid,nodev,lowerdir=${target},upperdir=${upper},workdir=${work}" none "${target}"
    fi
}

mount -t tmpfs -o rw,noexec,nosuid,nodev none /tmp
mount -t tmpfs -o rw,noexec,nosuid,nodev none /var/tmp
mount -t tmpfs -o rw,noexec,nosuid,nodev none /var/log
mount -t tmpfs -o rw,noexec,nosuid,nodev none /var/lib
mount -t tmpfs -o rw,noexec,nosuid,nodev none /var/cache
mount_overlay /usr/share/nvidia

echo "Starting guest GPU daemon service [595.58.03]..." | tee /dev/console
export LD_LIBRARY_PATH=/opt/nvidia-host/595.58.03/lib64:$LD_LIBRARY_PATH

# Modify config
sed -i 's/PARTITION_RAIL_POLICY=greedy/PARTITION_RAIL_POLICY=symmetric/' /usr/share/nvidia/nvswitch/fabricmanager.cfg

# Get port GUID
export port_guid="$(ibstat | grep -oE '(GUID:\ )(0x[a-z0-9]+)' | grep -oE -m 1 '0x[a-z0-9]+')"
echo "Using Port GUID: ${port_guid}" | tee /dev/console

# Start nvlsm
/opt/nvidia/nvlsm/sbin/nvlsm -F /usr/share/nvidia/nvlsm/nvlsm.conf 2>&1 | tee /dev/console &

# Start fabricmanager
/usr/bin/nv-fabricmanager -c /usr/share/nvidia/nvswitch/fabricmanager.cfg -g ${port_guid} 2>&1 | tee /dev/console &
# Wait for fabric manager to initialize
echo "Waiting for fabric manager to initialize..." | tee /dev/console
sleep 10

# Check readiness of the fabric
echo "Checking fabric readiness..." | tee /dev/console
for i in {1..15}; do
    fabric_output=$(nvidia-smi -q | grep -E '^\s*Fabric$' -A 1)
    echo "$fabric_output" | tee /dev/console
    
    fabric_count=$(echo "$fabric_output" | grep -c "Fabric")
    completed_count=$(echo "$fabric_output" | grep -c "Completed")
    
    if [ "$fabric_count" -gt 0 ] && [ "$fabric_count" -eq "$completed_count" ]; then
        echo "Fabric readiness completed for all GPUs." | tee /dev/console
        break
    fi
    
    echo "Fabric not ready yet (Completed: $completed_count/$fabric_count). Retrying in 2s..." | tee /dev/console
    sleep 2
done

# Keep container running by sleeping infinity, since background tasks might fork and exit
echo "Services started. Waiting indefinitely..." | tee /dev/console
sleep infinity

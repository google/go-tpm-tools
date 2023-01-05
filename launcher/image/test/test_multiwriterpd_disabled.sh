#!/bin/bash
set -euo pipefail

echo 'Running multi-writer PD test'

# grep -z reads the whole input, and -v inverts matches.
from_src_image=$(gcloud beta compute disks create --image-family confidential-space --image-project confidential-space-images --multi-writer test-multi-writer-img --zone us-west1-a 2>&1 || true)
if echo "$from_src_image" | grep -vz 'Cannot create a multi-writer disk from a source image'; then
    echo "$from_src_image"
    echo 'Multi-writer PD creation from image source enabled.'
    echo 'TEST FAILED.' > /workspace/status.txt
fi

DISK_NAME="source-boot-disk-$BUILD_ID"
echo "Creating PD $DISK_NAME"
gcloud compute disks create --image-family confidential-space --image-project confidential-space-images $DISK_NAME --zone us-west1-a

from_src_disk=$(gcloud beta compute disks create test-multi-writer-disk --source-disk=$DISK_NAME --multi-writer --zone us-west1-a 2>&1 || true)
# Cleanup disk before seeing test result.
gcloud compute disks delete $DISK_NAME -q --zone us-west1-a
if echo "$from_src_disk" | grep -vz 'Cannot create a multi-writer disk from a source disk'; then
    echo "$from_src_disk"
    echo 'Multi-writer PD creation from boot disk source enabled.'
    echo 'TEST FAILED.' > /workspace/status.txt
fi

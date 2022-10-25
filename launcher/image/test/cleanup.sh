#!/bin/bash
set -euo pipefail

if [ $CLEANUP != "true" ]; then
  echo "NOT cleaning up."
  exit 0
fi
echo "Cleaning up."
VM_NAME=$(cat /workspace/vm_name.txt)

echo 'Deleting VM' $VM_NAME
gcloud compute instances delete $VM_NAME --zone us-central1-a -q

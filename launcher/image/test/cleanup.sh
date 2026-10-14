#!/bin/bash
# cleanup.sh <VM_NAME> [<ZONE>]
set -euo pipefail

if [ $CLEANUP != "true" ]; then
  echo "NOT cleaning up."
  exit 0
fi
echo "Cleaning up."

VM_NAME=$1
# Empty zone means the VM was already deleted.
ZONE=$(gcloud compute instances list --filter="name=$VM_NAME" --format='value(zone.basename())')
if [ -z "$ZONE" ]; then
  echo "VM $VM_NAME already deleted."
  exit 0
fi

echo 'Deleting VM' $VM_NAME 'in zone' $ZONE
gcloud compute instances delete $VM_NAME --zone $ZONE -q

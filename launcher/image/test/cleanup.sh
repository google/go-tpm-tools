#!/bin/bash
# cleanup.sh <VM_NAME> [<ZONE>]
set -euo pipefail

if [ $CLEANUP != "true" ]; then
  echo "NOT cleaning up."
  exit 0
fi
echo "Cleaning up."

VM_NAME=$1
# If not provided, look up the zone by VM name.
ZONE=${2:-}
if [ -z "$ZONE" ]; then
  ZONE=$(gcloud compute instances list --filter="name=$VM_NAME" --format='value(zone.basename())')
fi

echo 'Deleting VM' $VM_NAME 'in zone' $ZONE
gcloud compute instances delete $VM_NAME --zone $ZONE -q

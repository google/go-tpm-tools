#!/bin/bash
# cleanup.sh <VM_NAME> <ZONE>
set -euo pipefail

if [ $CLEANUP != "true" ]; then
  echo "NOT cleaning up."
  exit 0
fi
echo "Cleaning up."

echo 'Deleting VM' $1 'in zone' $2 
gcloud compute instances delete $1 --zone $2 -q

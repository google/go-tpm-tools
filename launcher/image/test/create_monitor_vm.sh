#!/bin/bash
set -euxo pipefail

print_usage() {
    echo "usage: create_monitor_vm.sh [-n instanceName] [-z instanceZone]"
    echo "  -n <instanceName>: instance name"
    echo "  -z <instanceZone>: instance zone"
    exit 1
}

create_vm() {
  if [ -z "$VM_NAME" ]; then
    echo "Empty instance name supplied."
    exit 1
  fi

  if [ -z "$ZONE" ]; then
    echo "Empty zone supplied."
    exit 1
  fi

  LATEST_DEBIAN=$(gcloud compute images list \
      --project=debian-cloud \
      --no-standard-images \
      --filter="architecture=X86_64" \
      --format="value(family)" | sort -V | uniq | tail -n 1)

  if [ -z "$LATEST_DEBIAN" ]; then
    echo "Failed to find a Debian image family. Defaulting to debian-12."
    LATEST_DEBIAN="debian-12"
  else
    echo "Found latest Debian family: $LATEST_DEBIAN"
  fi

  echo "Creating monitor VM ${VM_NAME}"

  gcloud compute instances create "${VM_NAME}" \
    --zone "${ZONE}" \
    --machine-type=e2-micro \
    --image-family="${LATEST_DEBIAN}" \
    --image-project="debian-cloud" \
    --metadata=startup-script="#!/bin/bash
        apt-get update
        apt-get install -y netcat-openbsd
        nc -l -u -p 2020 > /dev/ttyS0"
}

VM_NAME=''
ZONE=''

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, n: means -n takes an additional argument.
while getopts 'n:z:' flag; do
  case "${flag}" in
    n) VM_NAME=${OPTARG} ;;
    z) ZONE=${OPTARG} ;;
    *) print_usage ;;
  esac
done

create_vm

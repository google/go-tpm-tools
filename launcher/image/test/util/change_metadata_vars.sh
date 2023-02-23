#!/bin/bash
set -euxo pipefail

print_usage() {
    echo "usage: change_metadata_vars.sh -n instanceName -z instanceZone [-m metadata] [-f metadataFromFile]"
    echo "  -m <metadata>: metadata variables on VM creation; passed directly into gcloud"
    echo "  -f <metadataFromFile>: read a metadata value from a file; specified in format key=filePath"
    echo "  -n <instanceName>: instance name"
    echo "  -z <instanceZone>: instance zone"
    exit 1
}

update_metadata() {
  if [ -z "${VM_NAME}" ]; then
    echo "Empty VM name supplied."
    exit 1
  fi

  if [ -z "${ZONE}" ]; then
    echo "Empty zone supplied."
    exit 1
  fi
  APPEND_ZONE="--zone ${ZONE}"

  if [ -z "${METADATA}${METADATA_FILE}" ]; then
    echo "Empty metadata supplied."
    exit 1
  fi

  APPEND_METADATA=''
  if ! [ -z "${METADATA}" ]; then
    APPEND_METADATA="--metadata ${METADATA}"
  fi

  APPEND_METADATA_FILE=''
  if ! [ -z "${METADATA_FILE}" ]; then
    APPEND_METADATA_FILE="--metadata-from-file ${METADATA_FILE}"
  fi

  echo "Updating VM ${VM_NAME} in ${ZONE} with metadata: ${METADATA_FILE} ${METADATA}"

  # check the active account
  gcloud auth list

  gcloud compute instances add-metadata $VM_NAME \
    $APPEND_ZONE $APPEND_METADATA $APPEND_METADATA_FILE
}

METADATA_FILE=''
METADATA=''
VM_NAME=''
ZONE=''

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'f:m:n:z:' flag; do
  case "${flag}" in
    f) METADATA_FILE=${OPTARG} ;;
    m) METADATA=${OPTARG} ;;
    n) VM_NAME=${OPTARG} ;;
    z) ZONE=${OPTARG} ;;
    *) print_usage ;;
  esac
done

update_metadata

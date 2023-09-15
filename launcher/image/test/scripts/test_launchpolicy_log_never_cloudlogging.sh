#!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

# Allow VM some time to boot and write to cloud logging.
sleep 120

CLOUD_LOGGING_OUTPUT=$(read_cloud_logging $1)
if echo $CLOUD_LOGGING_OUTPUT | grep -q 'logging redirection not allowed by image'
then
    echo "- Log launch policy verified"
else
    echo "FAILED: Log launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $CLOUD_LOGGING_OUTPUT
fi

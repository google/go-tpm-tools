#!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

# Allow VM some time to boot and write to serial console.
sleep 120

CLOUD_LOGGING_OUTPUT=$(read_cloud_logging $1)
if echo $CLOUD_LOGGING_OUTPUT | grep -q 'CMD is not allowed to be overridden on this image'
then
    echo "- CMD launch policy verified"
else
    echo "FAILED: CMD launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $CLOUD_LOGGING_OUTPUT
fi

#!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

# Allow VM some time to boot and write to cloud logging.
sleep 120

CLOUD_LOGGING_OUTPUT=$(read_cloud_logging $1)
if echo $CLOUD_LOGGING_OUTPUT | grep -q --fixed-strings 'env var {OUT a} is not allowed to be overridden on this image; allowed envs to be overridden: [ALLOWED_OVERRIDE]'
then
    echo "- Env launch policy verified"
else
    echo "FAILED: Env launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $CLOUD_LOGGING_OUTPUT
fi

#!/bin/bash
set -euo pipefail

echo "Checking the status.txt file for test results:"
if [ -f /workspace/status.txt ]; then
  cat /workspace/status.txt
  if grep -qi 'failed' /workspace/status.txt; then
    echo "The test failed for build $BUILD_ID."
    exit 1
  else
    echo "No test failure found."
    exit
  fi
else
  echo "No status.txt file found."
fi

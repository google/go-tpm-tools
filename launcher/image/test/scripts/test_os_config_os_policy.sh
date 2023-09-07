#!/bin/bash
set -euo pipefail

if $1 == 'debug'
then
    echo 'Running OS Config OS Policy enabled test'
else
    echo 'Running OS Config OS Policy disabled test'
fi

cat <<EOT >> shutdown-ospolicy.yaml
osPolicies:
  - id: shutdown-policy
    mode: ENFORCEMENT
    resourceGroups:
      - resources:
          id: shutdown-vm
          exec:
            validate:
              interpreter: SHELL
              script: if true; then sudo shutdown now; else exit 101; fi
            enforce:
              interpreter: SHELL
              script: exit 100
instanceFilter:
  inclusionLabels:
    - labels:
        shutdown-label: $2
rollout:
  disruptionBudget:
    percent: 100
  minWaitDuration: 1s
EOT

gcloud compute instances add-labels $2 --labels=shutdown-label=$2 --zone=$3 || true
GCLOUD_OUTPUT=$(gcloud compute os-config os-policy-assignments create shutdown-policy --location=$3 --file=shutdown-ospolicy.yaml | tail -1 || true)

if echo $GCLOUD_OUTPUT | grep -q 'Created OS policy assignment [shutdown-policy]'
then
    GCLOUD_OUTPUT=$(gcloud compute instances describe $2 --zone=$3 --format="value(status)" || true)
else
    echo 'TEST FAILED: OS policy assignment could not be created'
    echo 'TEST FAILED.' > /workspace/status.txt
    exit 1
fi

if $1 == 'debug'
then
    if echo $GCLOUD_OUTPUT | grep -q 'TERMINATED'
    then
        echo 'Success: OS policy assignment stops the VM'
    else
        echo 'TEST FAILED: VM did not terminate'
        echo 'TEST FAILED.' > /workspace/status.txt
    fi
else
    if echo $GCLOUD_OUTPUT | grep -q 'TERMINATED'
    then
        echo 'TEST FAILED: VM incorrectly terminated'
        echo 'TEST FAILED.' > /workspace/status.txt
    else
        echo 'Success: OS policy assignment does not affect VM'
    fi
fi

gcloud compute os-config os-policy-assignments delete shutdown-policy --location=$3 --quiet || true

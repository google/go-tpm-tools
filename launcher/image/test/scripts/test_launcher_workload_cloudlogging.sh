 #!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

# Allow VM some time to boot and write to cloud logging.
sleep 120

# This test requires the workload to run and print
# corresponding messages to cloud logging.
CLOUD_LOGGING_OUTPUT=$(read_cloud_logging $1) 
print_logs=false

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'Workload running'
then
    echo "- workload running verified"
else
    echo "FAILED: workload not running"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'Workload args: \[/main newCmd\]'
then
    echo "- arguments verified"
else
    echo "FAILED: arguments not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'env_bar=val_bar'
then
    echo "- env_bar env var verified"
else
    echo "FAILED: env_bar env not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'ALLOWED_OVERRIDE=overridden'
then
    echo "- ALLOWED_OVERRIDE env var verified"
else
    echo "FAILED: ALLOWED_OVERRIDE env not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'aud: https://sts.googleapis.com'
then
    echo "- token aud verified"
else
    echo "FAILED: token aud not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'iss: https://confidentialcomputing.googleapis.com'
then
    echo "- token iss verified"
else
    echo "FAILED: token iss not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'secboot: true'
then
    echo "- token secboot verified"
else
    echo "FAILED: token secboot not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'oemid: 11129'
then
    echo "- token oemid verified"
else
    echo "FAILED: token oemid not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'hwmodel: GCP_AMD_SEV'
then
    echo "- token hwmodel verified"
else
    echo "FAILED: token hwmodel not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'swname: GCE'
then
    echo "- token swname verified"
else
    echo "FAILED: token swname not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if echo $CLOUD_LOGGING_OUTPUT | grep -q 'Token looks okay'
then
    echo "- OIDC token accessible"
else
    echo "FAILED: OIDC token not accessible"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_logs=true
fi

if $print_logs; then
    echo $CLOUD_LOGGING_OUTPUT
fi

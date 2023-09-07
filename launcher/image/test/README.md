This directory contains the image integration tests.

# Tests
Integration tests run on [Cloud Build](https://cloud.google.com/build).
Run the test with `gcloud builds submit --config=test_{image_type}_cloudbuild.yaml`

# Development
When writing a test, determine whether it should target the hardened image,
debug image, or both. Add it to the corresponding test `test_{image_type}_cloudbuild.yaml`
file.

If there need to be multiple scripts, please suffix the script with the test name in each script.

For example, testing `new_feature` might use three scripts:
`test_newfeature_initresource.sh`, `test_newfeature_validate.sh`, and `test_newfeature_cleanupresource.sh`.

## Common Steps
Hardened and debug tests will include common steps that do test setup and cleanup activities.
They look like:

```yaml
- name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  env:
  - 'CLEANUP=$_CLEANUP'
  args: ['cleanup.sh']
```

* `create_vm.sh` creates a VM with the given image project, image name, and metadata. It then caches the VM name in the Cloud Build workspace.
* `cleanup.sh` deletes the VM created in create_vm.sh.
* `check_failure.sh` checks for a failure message in the status.txt file from a previous test step. This runs last due to Cloud Build exiting on previous step failures.

## Data
`data/` contains data that will be loaded as Metadata or onto the VM directly.

## Utils
Scripts in `util/` contain functions that can be sourced from other test scripts.

* `read_serial.sh` contains a helper to pull the entire serial log for a VM.

## Sharing Data Between Steps
`/workspace` is used in Cloud Build as a scratch space for specific builds. Some conventions for Confidential Space tests:

* `/workspace/status.txt` contains the success/failure message from test steps.
`check_failure.sh` looks for a failed message in the step to determine whether
the cloud build is successful.
* `workspace/next_start.txt` is used when reading the serial logs.

## Test Failures
Due to the sequential/only-proceed-with-success nature of Cloud Build, tests
with non-zero exit codes will cause subsequent steps to fail. This is
problematic when cleanup of a VM or other resources do not occur.

To avoid this issue, test assertions with non-zero exit codes should shell OR (`||`) the result
and place a "Test failed" message in `/workspace/status.txt`.

For example, `echo $SERIAL_OUTPUT | grep 'Expected output'` will fail and cancel
the rest of the Cloud Build on not finding the string "Expected output" in the
serial log.
The test writer should modify this line to do:

```bash
echo $SERIAL_OUTPUT | grep 'Expected output' || echo 'TEST FAILED' > /workspace/status.txt
# Optionally, for debugging:
echo $SERIAL_OUTPUT > /workspace/status.txt
```

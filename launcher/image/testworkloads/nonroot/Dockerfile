# Run this from the current directory:
# gcloud builds submit . --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/nonroot-container:latest --project confidential-space-images-dev

FROM python:3.11-slim

WORKDIR /app

COPY workload.py /app/workload.py

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"
# This launch policy makes the continer run as non-root.
LABEL "tee.launch_policy.nonroot_container"="true"

# Run unbuffered Python to ensure instant logging
ENTRYPOINT ["python3", "-u", "/app/workload.py"]

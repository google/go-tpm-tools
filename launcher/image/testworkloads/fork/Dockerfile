# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/fork-workload:latest --project confidential-space-images-dev

FROM python:3.11-slim

WORKDIR /app

COPY workload.py /app/workload.py

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"

# Run unbuffered Python to ensure instant logging
ENTRYPOINT ["python3", "-u", "/app/workload.py"]

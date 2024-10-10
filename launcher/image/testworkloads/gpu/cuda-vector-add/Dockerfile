# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/gpu/cuda-vector-add:latest --project confidential-space-images-dev
FROM gcr.io/google_containers/cuda-vector-add:v0.1

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"
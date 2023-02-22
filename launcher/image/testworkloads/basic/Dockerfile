# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main .
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/basic_test:latest
FROM alpine

COPY main /

ENV env_bar="val_bar"

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"

ENTRYPOINT ["/main"]

# Can be overridden because of the launch policy.
CMD ["arg_foo"]

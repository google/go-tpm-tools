# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main ../basic
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/allmonitoring:latest --project confidential-space-images-dev
FROM alpine

COPY main /

LABEL "tee.launch_policy.hardened_monitoring"="ALL"
LABEL "tee.launch_policy.debug_monitoring"="ALL"

ENTRYPOINT ["/main"]

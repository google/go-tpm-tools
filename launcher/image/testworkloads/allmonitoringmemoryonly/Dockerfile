# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main ../basic
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/allmonitoringmemory:latest --project confidential-space-images-dev
FROM alpine

COPY main /

ENV env_bar="val_bar"

LABEL "tee.launch_policy.hardened_monitoring"="MEMORYONLY"
LABEL "tee.launch_policy.debug_monitoring"="MEMORYONLY"

ENTRYPOINT ["/main"]

CMD ["arg_foo"]
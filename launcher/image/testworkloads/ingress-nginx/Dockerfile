# From the current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/nginx-unprivileged:latest
FROM docker.io/nginxinc/nginx-unprivileged:latest


# Remove the symlinks to stdout/stderr
RUN rm /var/log/nginx/access.log /var/log/nginx/error.log

# Direct NGINX to write to a writable /tmp directory by default
RUN ln -sf /tmp/access.log /var/log/nginx/access.log && \
    ln -sf /tmp/error.log /var/log/nginx/error.log

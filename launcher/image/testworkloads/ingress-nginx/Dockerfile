# From the current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/nginx-custom:latest
FROM docker.io/library/nginx:latest

USER root

# Change the listening port from 80 to 8080 in the default config
RUN sed -i 's/listen\s*80;/listen 8080;/g' /etc/nginx/conf.d/default.conf

# Remove the symlinks to stdout/stderr
RUN rm /var/log/nginx/access.log /var/log/nginx/error.log

# Direct NGINX to write to a writable /tmp directory by default
RUN ln -sf /tmp/access.log /var/log/nginx/access.log && \
    ln -sf /tmp/error.log /var/log/nginx/error.log

USER nginx

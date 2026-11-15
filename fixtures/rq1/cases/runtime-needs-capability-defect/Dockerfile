# RQ1 corpus case: runtime-needs-capability-defect
# Defect: runs as root and chowns /opt/data at start, which needs CAP_CHOWN.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app && mkdir -p /opt/data
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
ENTRYPOINT ["/bin/sh", "-c", "chown 10001:10001 /opt/data || exit 1; trap 'exit 0' TERM; sleep 3600 & wait $!"]

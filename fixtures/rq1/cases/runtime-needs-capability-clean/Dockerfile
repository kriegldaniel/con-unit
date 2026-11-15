# RQ1 corpus case: runtime-needs-capability-clean
# Control: ownership fixed at build time, unprivileged user, no capability needed at start.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app && mkdir -p /opt/data && chown 10001:10001 /opt/data
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

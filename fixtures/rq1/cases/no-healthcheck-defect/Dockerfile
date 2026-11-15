# RQ1 corpus case: no-healthcheck-defect
# Defect: no HEALTHCHECK instruction.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

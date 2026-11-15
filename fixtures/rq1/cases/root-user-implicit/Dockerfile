# RQ1 corpus case: root-user-implicit
# Defect: no USER instruction, the container runs as UID 0.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

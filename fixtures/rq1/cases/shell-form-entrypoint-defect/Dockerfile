# RQ1 corpus case: shell-form-entrypoint-defect
# Defect: shell-form ENTRYPOINT with two commands, so /bin/sh stays PID 1 and does not forward SIGTERM.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT sleep 3600 && echo done

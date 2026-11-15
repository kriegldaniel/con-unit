# RQ1 corpus case: package-cache-defect
# Defect: apk update leaves the package index under /var/cache/apk. Needs network at build time.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
RUN apk update && apk add tzdata
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

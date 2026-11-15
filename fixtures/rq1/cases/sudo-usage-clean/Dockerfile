# RQ1 corpus case: sudo-usage-clean
# Control: the same directory is created and owned by the application user without sudo.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
RUN mkdir -p /home/app/data && chown 10001:10001 /home/app/data
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

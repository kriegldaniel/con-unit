# RQ1 corpus case: setuid-binary-clean
# Control: the same copy of busybox with mode 0755.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
RUN cp /bin/busybox /usr/local/bin/seeded-tool && chmod 0755 /usr/local/bin/seeded-tool
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

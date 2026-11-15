# RQ1 corpus case: nonroot-privileged-port-defect
# Defect: a non-root image whose listener binds port 80 at start, without an EXPOSE instruction, so only a run shows it. No network needed.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "nc -l -p 80 & pid=$!; trap 'kill $pid; exit 0' TERM; wait $pid"]

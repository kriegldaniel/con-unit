# RQ1 corpus case: writes-outside-tmp-clean
# Control: the same state file is written under /tmp. No network needed.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
ENTRYPOINT ["/bin/sh", "-c", "echo started > /tmp/rq1-state || exit 1; trap 'exit 0' TERM; sleep 3600 & wait $!"]

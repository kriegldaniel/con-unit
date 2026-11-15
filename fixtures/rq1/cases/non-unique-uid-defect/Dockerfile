# RQ1 corpus case: non-unique-uid-defect
# Defect: two accounts, app and app2, share UID 10001 in /etc/passwd. No network needed at build time.
FROM docker.io/library/debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
RUN useradd --uid 10001 --no-create-home app && useradd --non-unique --uid 10001 --no-create-home app2
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

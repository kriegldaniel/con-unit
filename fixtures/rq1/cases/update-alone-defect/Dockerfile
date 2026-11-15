# RQ1 corpus case: update-alone-defect
# Defect: apt-get update runs in its own RUN step, so the package index is cached as a layer on its own. Needs network at build time.
FROM docker.io/library/debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
RUN useradd --uid 10001 --no-create-home app
RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

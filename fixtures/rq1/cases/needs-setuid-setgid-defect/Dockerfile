# RQ1 corpus case: needs-setuid-setgid-defect
# Defect: starts as root and drops to the application user with su before it runs the application (the su-exec pattern).
# The drop calls setgroups, setgid and setuid, so it needs CAP_SETUID and CAP_SETGID together and the image does not start with all capabilities dropped. No network needed.
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
ENTRYPOINT ["su", "app", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

# RQ1 corpus case: private-key-file-defect
# Defect: server.key holding a PEM private key block (random body, not a usable key).
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
RUN mkdir -p /opt/app \
 && { echo "-----BEGIN RSA PRIVATE KEY-----"; head -c 1190 /dev/urandom | base64; echo "-----END RSA PRIVATE KEY-----"; } > /opt/app/server.key
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

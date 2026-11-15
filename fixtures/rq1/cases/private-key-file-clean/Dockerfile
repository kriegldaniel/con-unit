# RQ1 corpus case: private-key-file-clean
# Control: server.pem holding a PEM public key block (random body).
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN adduser -D -u 10001 app
RUN mkdir -p /opt/app \
 && { echo "-----BEGIN PUBLIC KEY-----"; head -c 294 /dev/urandom | base64; echo "-----END PUBLIC KEY-----"; } > /opt/app/server.pem
HEALTHCHECK --interval=30s --timeout=3s CMD ["true"]
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait $!"]

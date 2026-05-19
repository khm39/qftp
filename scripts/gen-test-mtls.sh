#!/usr/bin/env bash
# Generate a self-signed CA plus a server cert and a client cert for local
# mTLS testing. Output goes to ./tls-test/. Do not use the resulting
# material outside of development.
set -euo pipefail
# Refuse to create world- or group-readable files in this script, since
# we're generating private keys. Individual `chmod` calls below pin the
# expected modes explicitly so the result is stable regardless of the
# caller's environment.
umask 077

out="${1:-tls-test}"
mkdir -p "$out"
cd "$out"

# 1. CA
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -subj "/CN=qftp-test-ca" \
    -keyout ca.key -out ca.crt
chmod 600 ca.key
chmod 644 ca.crt

# 2. Server (CN=localhost so the client can verify against it)
openssl req -nodes -newkey rsa:2048 \
    -subj "/CN=localhost" \
    -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 365 -out server.crt \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
chmod 600 server.key
chmod 644 server.crt

# 3. Client (CN identifies the user, server's --client-ca enforces mTLS)
openssl req -nodes -newkey rsa:2048 \
    -subj "/CN=qftp-test-client" \
    -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 365 -out client.crt
chmod 600 client.key
chmod 644 client.crt

rm -f server.csr client.csr ca.srl

cat <<EOF

Generated in $out/:
  ca.crt        -- root CA (pass to --ca on the client, --client-ca on server)
  server.crt    -- server cert (pass to --cert)
  server.key    -- server key  (pass to --key)
  client.crt    -- client cert (pass to --client-cert)
  client.key    -- client key  (pass to --client-key)

Example:
  qftp-server  --cert server.crt --key server.key --client-ca ca.crt
  qftp-client  --ca ca.crt --client-cert client.crt --client-key client.key
EOF

#!/usr/bin/env bash
#
# Generates a self-signed TLS certificate for local/docker use, since there's no
# public domain here for a real CA (Let's Encrypt etc.) to issue against.
#
# Idempotent: does nothing if certs/dev.crt and certs/dev.key both already
# exist, so re-running `make up` doesn't rotate the cert under a running nginx.
# Delete certs/ and re-run to force a fresh one.
#
#     bash scripts/gen-dev-cert.sh
#
# The private key never leaves this machine — certs/ is gitignored.

set -euo pipefail

cd "$(dirname "$0")/.."

# Without this, Git Bash sees the leading "/" in -subj's "/CN=..." value and
# "helpfully" rewrites it into a Windows path (e.g. "C:/Program Files/Git/CN=...")
# before openssl ever sees it — same class of bug documented in
# scripts/win-env.sh. Sourcing it here rather than duplicating it keeps the fix
# in one place.
source "$(dirname "$0")/win-env.sh"

CERT_DIR="certs"
CERT="${CERT_DIR}/dev.crt"
KEY="${CERT_DIR}/dev.key"
DAYS=825 # the longest validity most tooling (including recent browsers) accepts without complaint

if [[ -f "$CERT" && -f "$KEY" ]]; then
    echo "==> ${CERT} and ${KEY} already exist, leaving them alone"
    echo "    (delete ${CERT_DIR}/ and re-run to generate a fresh cert)"
    exit 0
fi

mkdir -p "$CERT_DIR"

echo "==> generating a self-signed dev certificate (${DAYS} days)"

# SAN covers every name a client actually connects with: "nginx" is what the
# load generator and any other container resolve on the compose network,
# "localhost"/127.0.0.1 cover a host browser or curl hitting the published port.
openssl req -x509 -nodes \
    -newkey rsa:2048 \
    -days "$DAYS" \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/CN=secure-auth-gateway-dev" \
    -addext "subjectAltName=DNS:nginx,DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY"

echo "==> wrote ${CERT} and ${KEY}"
echo "    self-signed — clients must skip verification or trust this cert explicitly"

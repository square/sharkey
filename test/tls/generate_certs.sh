#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DIR=$(mktemp -d)

function cleanup() {
  echo "Cleanup..."
  rm -rf "$DIR"
}

trap cleanup EXIT

# Generate new root cert
certstrap --depot-path "$DIR" init --common-name "CertAuth" --expires "10 years"

# Generate server cert
certstrap --depot-path "$DIR" request-cert --ip 127.0.0.1 --domain server
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" server

# Generate client cert
certstrap --depot-path "$DIR" request-cert --ip 127.0.0.1 --domain client
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" client

for i in client.key client.crt server.key server.crt CertAuth.key CertAuth.crt; do
  mv "$DIR/$i" "$BASEDIR/"
done

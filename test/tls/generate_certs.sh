#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DIR=$(mktemp -d)

function cleanup() {
  echo "Cleanup..."
  #rm -rf "$DIR"
}

trap cleanup EXIT

echo "Generate new root cert"
certstrap --depot-path "$DIR" init --passphrase "" --common-name "CertAuth" --expires "10 years"

echo "Generate server cert"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain server
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" server

echo "Generate server cert with SPIFFE URI"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain server \
  --key "$DIR/server.key" --uri spiffe://sharkey.test/sharkey-server --csr "$DIR/server_spiffe.csr"
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" \
  --csr "$DIR/server_spiffe.csr" --cert "$DIR/server_spiffe.crt" serverwithspiffe

echo "Generate client cert"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain client
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" client

echo "Generate client cert with SPIFFE URI"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain clientwithspiffe \
  --uri spiffe://sharkey.test/sharkey-client/client  --csr "$DIR/client_spiffe.csr" \
  --key "$DIR/client.key"
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" \
  --csr "$DIR/client_spiffe.csr" --cert "$DIR/client_spiffe.crt" clientwithspiffe

echo "Generate proxy cert"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain proxy
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" proxy

echo "Generate bad cert"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain badCert
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" badCert

echo "Generate bad cert with SPIFFE URI"
certstrap --depot-path "$DIR" request-cert --passphrase "" --ip 127.0.0.1 --domain badcertwithspiffe \
  --uri spiffe://sharkey.test/some-app/badcertwithspiffe  --csr "$DIR/bad_cert_with_spiffe.csr" \
  --key "$DIR/bad_cert_with_spiffe.key"
certstrap --depot-path "$DIR" sign --CA CertAuth --expires="10 years" \
  --csr "$DIR/bad_cert_with_spiffe.csr" --cert "$DIR/bad_cert_with_spiffe.crt" badcertwithspiffe


for i in client.key client.crt server.key server.crt CertAuth.key CertAuth.crt \
client_spiffe.crt server_spiffe.crt badCert.key badCert.crt bad_cert_with_spiffe.key \
bad_cert_with_spiffe.crt proxy.key proxy.crt; do
  mv "$DIR/$i" "$BASEDIR/"
done

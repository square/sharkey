#!/bin/bash

set -e
set -o pipefail
set -x

TMPDIR=$(mktemp -d)

function die() {
  echo "$1"
  exit 1
}

function wait_for_container() {
  echo "Waiting for $1..."
  for i in range 0 20; do
    if docker ps | grep -q "$1"; then
      return
    fi
    sleep 1
  done
  die "timed out waiting on container $1"
}

function cleanup() {
  echo "Cleanup..."
  docker logs server
  docker logs client
  docker stop client -t 20  || die "failed to stop 'client'"
  docker stop server -t 20  || die "failed to stop 'server'"
  rm -r "$TMPDIR"  || die "failed to remove '$TMPDIR'"
}

trap cleanup EXIT

BUILD_CONTEXT=/build
SERVER_CONFIG="${BUILD_CONTEXT}/test/integration/server_config.yaml"
MIGRATION_CONFIG="${BUILD_CONTEXT}/db/sqlite"
CLIENT_CONFIG="${BUILD_CONTEXT}/test/integration/client_config.yaml"

echo Starting sharkey server container

# Start server
docker run -d --rm \
	--name=server \
	-v "$PWD":"$BUILD_CONTEXT" \
	-e SHARKEY_CONFIG="$SERVER_CONFIG" \
	-e SHARKEY_MIGRATIONS="$MIGRATION_CONFIG" \
	-p 12321:8080 \
	server start

wait_for_container server

echo Starting sharkey client container

# Start client
docker run -d --rm \
	--name client \
	-v "$PWD":"$BUILD_CONTEXT" \
	-e SHARKEY_CONFIG="$CLIENT_CONFIG" \
	-p 14296:22 \
	--link server \
	--hostname client \
	client

wait_for_container client

# Give client some time to finish initializing
sleep 5

echo "Starting integration test"

echo "Signing user ssh key"
# Sign user ssh key
# NOTE: on MacOS ensure that your curl it built with openssl (and not SecureTransport)
#       or you won't be able to load client cert from PEM file
curl --cert $PWD/test/tls/proxy.crt --key $PWD/test/tls/proxy.key \
  https://localhost:12321/enroll_user -H "X-Forwarded-User: alice" \
  -d @$PWD/test/ssh/alice_rsa.pub -k \
  -o $TMPDIR/alice_rsa-cert.pub -sS

ssh-keygen -L -f $TMPDIR/alice_rsa-cert.pub

# SSH will want cert and identity file in the same dir
cp $PWD/test/ssh/alice_rsa* $TMPDIR/
chmod 600 $TMPDIR/alice_rsa


# Try sshing into container
if ! grep -q "127.0.0.1 client" /etc/hosts; then
  echo "127.0.0.1 client" | sudo tee -a /etc/hosts
fi

echo Attempting to ssh into client container
ssh -v -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@client true || die "failed to connect to 'client'"
ssh -v -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@localhost true || die "failed to connect to 'localhost'"

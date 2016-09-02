#!/bin/bash

set -e
set -o pipefail

function die() {
  echo "$1"
  exit 1
}

function wait_for_container() {
  echo "Waiting for $1..."
  for i in range 0 10; do
    if docker ps | grep -q "$1"; then
      return
    fi
    sleep 1
  done
  die "timed out waiting on container $1"
}

function cleanup() {
  echo "Cleanup..."
  docker stop server
  docker stop client
  docker rm server
  docker rm client
}

trap cleanup EXIT

BUILD_CONTEXT=/build
SERVER_CONFIG="${BUILD_CONTEXT}/test/integration/server_config.yaml"
MIGRATION_CONFIG="${BUILD_CONTEXT}/db/sqlite"
CLIENT_CONFIG="${BUILD_CONTEXT}/test/integration/client_config.yaml"

echo Starting sharkey server container

# Start server
docker run -d \
	--name=server \
	-v "$PWD":"$BUILD_CONTEXT" \
	-e SHARKEY_CONFIG="$SERVER_CONFIG" \
	-e SHARKEY_MIGRATIONS="$MIGRATION_CONFIG" \
	server start

wait_for_container server

echo Starting sharkey client container

# Start client
docker run -d \
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

# Try sshing into container
if ! grep -q "127.0.0.1 client" /etc/hosts; then
  echo "127.0.0.1 client" | sudo tee -a /etc/hosts
fi

echo Attempting to ssh into client container

chmod 600 test/integration/id_rsa
ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i test/integration/id_rsa root@client true || die "failed to connect to 'client'"
ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i test/integration/id_rsa root@localhost true || die "failed to connect to 'localhost'"

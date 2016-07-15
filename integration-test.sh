#!/bin/bash

set -e
set -o pipefail

BUILD_CONTEXT=/build
SHARKEY_CONFIG="${BUILD_CONTEXT}/test/docker/server_config.yaml"
DOCKER_IP="127.0.0.1"

if which docker-machine; then
  # Assuming docker is running on a remote host instead of locally,
  # for example in a virtual machine for OS X setups. 
  DOCKER_IP=$(docker-machine ip)
fi

echo "Setting up new container database"

# Setup database
docker run \
  -v "$PWD":"$BUILD_CONTEXT" \
  -e SHARKEY_CONFIG="$SHARKEY_CONFIG" \
  square/sharkey-server migrate --migrations=/build/db/sqlite

echo "Launching docker container for server"

# Run sharkey server (in background)
CONTAINER_ID=$(docker run \
  -d -p 8080:8080 \
  -v "$PWD":"$BUILD_CONTEXT" \
  -e SHARKEY_CONFIG="$SHARKEY_CONFIG" \
  square/sharkey-server start)

echo "Running sharkey in container: $CONTAINER_ID"

# Setup cleanup hook
function cleanup {
  echo "Killing docker container"
  docker kill "$CONTAINER_ID"
}
trap cleanup EXIT

# Wait for server to be ready
sleep 5

# Connect to server status endpoint
wget -O status.out \
  --no-check-certificate \
  --ca-certificate test/tls/CertAuth.crt \
  --certificate test/tls/testCert.crt \
  --private-key test/tls/testCert.key \
  "https://${DOCKER_IP}:8080/_status"

echo "Status results:"
jq . < status.out

# TODO(cs): add client component to integration test

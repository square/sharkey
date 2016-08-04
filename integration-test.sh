#!/bin/bash

set -e
set -o pipefail

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
sleep 5

echo Starting sharkey client container

#Start client
docker run -d \
	--name client \
	-v "$PWD":"$BUILD_CONTEXT" \
	-e SHARKEY_CONFIG="$CLIENT_CONFIG" \
	-p 14296:22 \
	--link server \
	--hostname client \
	client

echo Attempting to ssh into client container

# try sshing into container
sleep 5
echo "127.0.0.1 client" | sudo tee -a /etc/hosts
chmod 600 test/integration/id_rsa
ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i test/integration/id_rsa root@client echo bleh
echo exit code: $?

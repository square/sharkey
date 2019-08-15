#!/bin/bash

set -e
#set -o pipefail

TMPDIR=$(mktemp -d)

function die() {
  echo "$1"
  cleanup
  exit 1
}

function wait_for_container() {
  echo "Waiting for $1..."
  for i in range 0 15; do
    if docker ps | grep -q "$1"; then
      return
    fi
    sleep 1
  done
  die "timed out waiting on container $1"
}

function cleanup() {
  echo "Cleanup..."
  rm -r "$TMPDIR"
  docker ps | grep 'server' > /dev/null
  if [[ $? = 0 ]]; then
    echo "Stoping 'server'"
    docker stop server > /dev/null
  fi

  docker ps | grep 'client' > /dev/null
  if [[ $? = 0 ]]; then
    echo "Stoping 'client'"
    docker stop client > /dev/null
  fi

  docker ps -a | grep 'server' > /dev/null
  if [[ $? = 0 ]]; then
    echo "Removing 'server'"
    docker rm server > /dev/null
  fi

  docker ps -a | grep 'client' > /dev/null
  if [[ $? = 0 ]]; then
    echo "Removing 'client'"
    docker rm client > /dev/null
  fi
  echo "DONE"
}

function start_containers() {
  echo Starting sharkey server container
  # Start server
  docker run -d \
  --name=server \
  -v "$PWD":"$BUILD_CONTEXT" \
  -e SHARKEY_CONFIG="$1" \
  -e SHARKEY_MIGRATIONS="$MIGRATION_CONFIG" \
  -p 12321:8080 \
  server start

  wait_for_container server

  echo Starting sharkey client container

  # Start client
  docker run -d \
  --name client \
  -v "$PWD":"$BUILD_CONTEXT" \
  -e SHARKEY_CONFIG="$2" \
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
}

function sign_ssh_cert() {
  echo "Signing user ssh key"
  # Sign user ssh key
  # NOTE: on MacOS ensure that your curl it built with openssl (and not SecureTransport)
  #       or you won't be able to load client cert from PEM file
  curl --cert $PWD/test/tls/proxy.crt --key $PWD/test/tls/proxy.key \
    https://localhost:12321/enroll_user/alice -H "X-Forwarded-User: alice" \
    -d @$PWD/test/ssh/alice_rsa.pub -k \
    -o $TMPDIR/alice_rsa-cert.pub -s

  ssh-keygen -L -f $TMPDIR/alice_rsa-cert.pub

  # SSH will want cert and identity file in the same dir
  cp $PWD/test/ssh/alice_rsa* $TMPDIR/
  chmod 600 $TMPDIR/alice_rsa
}

function run_success_test() {
  start_containers $1 $2 || die "failed to start containers"

  sign_ssh_cert

  echo "Attempting to ssh into client container"

  ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@client true || die "failed to connect to 'client'"
  ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@localhost true || die "failed to connect to 'localhost'"

  cleanup
}

function run_fail_test() {
  start_containers $1 $2 || die "failed to start containers"

  sign_ssh_cert

  echo "Attempting to ssh into client container"

  ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@client true && die "expected to fail to connect to 'client', but succeeded"
  ssh -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@localhost true && die "expected to fail to connect to 'localhost', but succeeded"
}

BUILD_CONTEXT=/build
MIGRATION_CONFIG="${BUILD_CONTEXT}/db/sqlite"
good_server_config="${BUILD_CONTEXT}/test/integration/server_config.yaml"
good_client_config="${BUILD_CONTEXT}/test/integration/client_config.yaml"
bad_client_config="${BUILD_CONTEXT}/test/integration/client_config_bad_cert.yaml"
good_server_spiffe_config="${BUILD_CONTEXT}/test/integration/server_spiffe_config.yaml"
good_client_spiffe_config="${BUILD_CONTEXT}/test/integration/client_spiffe_config.yaml"
bad_client_spiffe_config="${BUILD_CONTEXT}/test/integration/client_spiffe_config_bad_cert.yaml"


echo "===== Test 1: Enroll client using standard certs ====="
run_success_test $good_server_config $good_client_config
echo "===== Test 2: Fail to enroll client when hostname doesn't match ====="
run_fail_test $good_server_config $bad_client_config
echo "===== Test 3: Enroll client using SPIFFE identity ====="
run_success_test $good_server_spiffe_config $good_client_spiffe_config
echo "===== Test 4: Fail to enroll client when hostname in SPIFFE identity doesn't match====="
run_fail_test $good_server_spiffe_config $bad_client_spiffe_config

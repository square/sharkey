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
  for i in {1..20}; do
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
  docker logs server_pkcs11_ec_spec284r1
  docker logs server_pkcs11_ec_prime256v1
  docker logs client
  docker stop server_pkcs11_ec_spec284r1 -t 20  || die "failed to stop 'server_pkcs11'"
  docker stop server_pkcs11_ec_prime256v1 -t 20  || die "failed to stop 'server_pkcs11'"
  docker stop client -t 20  || die "failed to stop 'client'"
  docker stop server -t 20  || die "failed to stop 'server'"
  rm -r "$TMPDIR"  || die "failed to remove '$TMPDIR'"
}

function start_server() {
  MSYS_NO_PATHCONV=1 docker run -d --rm \
	--name=$1 \
	-v "$PWD":"$BUILD_CONTEXT" \
	-e SHARKEY_CONFIG=$2 \
	-e SHARKEY_MIGRATIONS="$MIGRATION_CONFIG" \
	-p $3:8080 \
	$4 start

wait_for_container $1
}

function test_server() {
  curl --cert $PWD/test/tls/proxy.crt --key $PWD/test/tls/proxy.key \
  https://localhost:$1/enroll_user -H "X-Forwarded-User: alice" \
  -d @$PWD/test/ssh/alice_rsa.pub -k \
  -o $TMPDIR/alice_rsa-cert.pub -sS

ssh-keygen -L -f $TMPDIR/alice_rsa-cert.pub

# Extract CA public key (Private key generated in "hardware")
docker cp $2:/sharkey/ca_pub_keys/$3 $TMPDIR/

# Convert to openssh format
CA_PUB_KEY_PEM_FORMAT=$3
CA_PUB_KEY_OPENSSH_FORMAT=${CA_PUB_KEY_PEM_FORMAT%.*}.pub
ssh-keygen -i -m PKCS8 -f $TMPDIR/$CA_PUB_KEY_PEM_FORMAT > $TMPDIR/$CA_PUB_KEY_OPENSSH_FORMAT

# Copy to client container
docker cp $TMPDIR/$CA_PUB_KEY_OPENSSH_FORMAT client:/etc/ssh/ca_user_key.pub

ssh -v -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@client true || die "failed to connect to 'client'"
ssh -v -p 14296 -o "BatchMode yes" -o "UserKnownHostsFile=test/integration/known_hosts" -i $TMPDIR/alice_rsa alice@localhost true || die "failed to connect to 'localhost'"
}

trap cleanup EXIT

BUILD_CONTEXT=/build
SERVER_CONFIG="${BUILD_CONTEXT}/test/integration/server_config.yaml"
SERVER_PKCS11_EC_PRIME256V1_CA_CONFIG="${BUILD_CONTEXT}/test/integration/server_pkcs11_ec_prime256v1_ca_config.yaml"
SERVER_PKCS11_EC_SPEC384R1_CA_CONFIG="${BUILD_CONTEXT}/test/integration/server_pkcs11_ec_spec384r1_ca_config.yaml"
MIGRATION_CONFIG="${BUILD_CONTEXT}/db/sqlite"
CLIENT_CONFIG="${BUILD_CONTEXT}/test/integration/client_config.yaml"

echo Starting sharkey server container

# Start server
start_server server $SERVER_CONFIG 12321 server

echo Starting sharkey client container

# Start client
MSYS_NO_PATHCONV=1 docker run -d --rm \
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
# NOTE: on MacOS ensure that your curl is built with openssl (and not SecureTransport)
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

declare -a test1=("server_pkcs11_ec_prime256v1" "$SERVER_PKCS11_EC_PRIME256V1_CA_CONFIG" "12421" "server_pkcs11" "pkcs11_ec_prime256v1_pub_key.pem")
declare -a test2=("server_pkcs11_ec_spec284r1" "$SERVER_PKCS11_EC_SPEC384R1_CA_CONFIG" "12521" "server_pkcs11" "pkcs11_ec_spec384r1_pub_key.pem")
declare -a pkcs11_tests=(test1 test2)

for args in "${pkcs11_tests[@]}"
do
  declare -n lst="$args"
  container_name=${lst[0]}
  sharkey_config=${lst[1]}
  container_port=${lst[2]}
  image_name=${lst[3]}
  ca_pub_key_filename=${lst[4]}

  start_server $container_name $sharkey_config $container_port $image_name
  test_server $container_port $container_name $ca_pub_key_filename
done

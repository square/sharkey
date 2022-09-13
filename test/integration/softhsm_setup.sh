#!/bin/sh

# Setup SoftHSM: initilize token, generate key, extract public key
# EC with prime256v1
softhsm2-util --init-token --slot 0 --label sharkey-test-token-ec_prime256v1 --pin 1234 --so-pin 4321
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --token-label sharkey-test-token-ec_prime256v1 --login --pin 1234 --keypairgen --key-type EC:prime256v1 --usage-sign
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --token-label sharkey-test-token-ec_prime256v1 --login --pin 1234 --read-object --type pubkey --label "" -o /sharkey/ca_pub_keys/pkcs11_ec_prime256v1_pub_key.der
openssl ec -pubin -inform DER -in /sharkey/ca_pub_keys/pkcs11_ec_prime256v1_pub_key.der -outform PEM -out /sharkey/ca_pub_keys/pkcs11_ec_prime256v1_pub_key.pem

# EC with secp384r1
softhsm2-util --init-token --slot 1 --label sharkey-test-token-ec-spec384r1 --pin 1234 --so-pin 4321
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --token-label sharkey-test-token-ec-spec384r1 --login --pin 1234 --keypairgen --key-type EC:secp384r1 --usage-sign
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --token-label sharkey-test-token-ec-spec384r1 --login --pin 1234 --read-object --type pubkey --label "" -o /sharkey/ca_pub_keys/pkcs11-ec_spec384r1_pub_key.der
openssl ec -pubin -inform DER -in /sharkey/ca_pub_keys/pkcs11-ec_spec384r1_pub_key.der -outform PEM -out /sharkey/ca_pub_keys/pkcs11_ec_spec384r1_pub_key.pem

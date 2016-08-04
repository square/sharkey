#!/bin/sh

## Docker container entry point

if [ -z "$SHARKEY_CONFIG" ]; then
    echo "No configuration file specified, aborting."
    exit 1
fi

/usr/sbin/sshd
/usr/bin/sharkey-client --config="$SHARKEY_CONFIG"

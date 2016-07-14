#!/bin/sh

## Docker container entry point

if [ -z "$SHARKEY_CONFIG" ]; then
    echo "No configuration file specified, aborting."
    exit 1
fi

exec /usr/bin/sharkey-server --config="$SHARKEY_CONFIG" "$@"

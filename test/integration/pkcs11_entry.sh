#!/bin/sh

## Docker container entry point

if [ -z "$SHARKEY_CONFIG" ]; then
    echo "No configuration file specified, aborting."
    exit 1
fi

if ! [ -z "$SHARKEY_MIGRATIONS" ]; then
	/usr/bin/sharkey-server migrate --config="$SHARKEY_CONFIG" --migrations="$SHARKEY_MIGRATIONS"
fi

# Start the server
exec /usr/bin/sharkey-server --config="$SHARKEY_CONFIG" "$@"

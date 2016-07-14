# Dockerfile for square/sharkey (server).
#
# Building:
#   docker build --rm -t square/sharkey-server .
#
# Basic usage:
#   docker run -e SHARKEY_CONFIG=/path/to/config square/sharkey-server
#
# This image only contains the server component of sharkey,
# the client will have to be deployed separately

FROM golang:alpine

MAINTAINER Cedric Staub "cs@squareup.com"

# Install CGO deps
RUN apk add --update gcc musl-dev && \
    rm -rf /var/cache/apk/*

# Copy source
COPY . /go/src/github.com/square/sharkey

# Build & cleanup
RUN cd /go/src/github.com/square/sharkey && \
    cp docker.sh /usr/bin/entrypoint.sh && \
    chmod +x /usr/bin/entrypoint.sh && \
    go build -v -o /usr/bin/sharkey-server ./server && \
    rm -rf /go/src/*

ENTRYPOINT ["/usr/bin/entrypoint.sh"]

# Dockerfile for square/sharkey (server).
#
# Building:
#   docker build --rm -t square/sharkey-server .
#
# Basic usage:
#   docker run -e SHARKEY_CONFIG=/path/to/config -e SHARKEY_MIGRATIONS=/path/to/migration/dir square/sharkey-server
#
# This image only contains the server component of sharkey,
# the client will have to be deployed separately

FROM golang:1.23 AS build

WORKDIR /app

# Copy source
COPY . .

# Download dependencies
RUN go mod download

# Build & set-up
RUN cp docker.sh /usr/bin/entrypoint.sh && \
    chmod +x /usr/bin/entrypoint.sh && \
    go build -buildvcs=false -o /usr/bin/sharkey-server github.com/square/sharkey/cmd/sharkey-server


# Create a multi-stage build with the binary
FROM gcr.io/distroless/base-debian9:nonroot AS build-release-stage

COPY --from=build /usr/bin/sharkey-server /usr/bin/sharkey-server
COPY --from=build /usr/bin/entrypoint.sh /usr/bin/entrypoint.sh

ENTRYPOINT ["/usr/bin/entrypoint.sh"]

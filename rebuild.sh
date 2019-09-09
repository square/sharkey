#!/usr/bin/env bash

docker build -t client:latest -f DockerfileClientTest . ; docker build -t server:latest -f Dockerfile .

docker stop server client
docker rm server client

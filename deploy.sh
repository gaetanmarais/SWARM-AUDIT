#!/bin/bash
set -e
git pull
podman compose down
GIT_HASH=$(git rev-parse --short HEAD) podman compose build --no-cache
podman compose up -d
echo "Deployed $(git rev-parse --short HEAD)"

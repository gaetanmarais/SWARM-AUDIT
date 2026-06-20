#!/bin/bash
set -e

KEEP_CONF=false
for arg in "$@"; do
  [ "$arg" = "--keep-conf" ] && KEEP_CONF=true
done

git pull
podman compose down

if [ "$KEEP_CONF" = false ]; then
  echo "Clearing audit/analysis data (use --keep-conf to preserve)..."
  rm -f data/inventory.json data/credentials.json
  rm -rf data/dumps/*
fi

GIT_HASH=$(git rev-parse --short HEAD) podman compose build --no-cache
podman compose up -d
echo "Deployed $(git rev-parse --short HEAD)"

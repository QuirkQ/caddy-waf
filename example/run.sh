#!/bin/sh
set -eu

cd "$(dirname "$0")"

BUILD=true
if [ "${1:-}" = "--no-build" ]; then
  BUILD=false
fi

cleanup() {
  echo ""
  echo "Cleaning up..."
  docker compose down --remove-orphans --volumes 2>/dev/null || true
}
trap cleanup EXIT

if [ "$BUILD" = "true" ]; then
  echo "Building image..."
  docker compose build --quiet
fi

echo "Starting services..."
docker compose up --exit-code-from test --abort-on-container-exit

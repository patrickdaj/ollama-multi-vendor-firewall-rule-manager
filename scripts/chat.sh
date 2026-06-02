#!/usr/bin/env bash
# Run fw-chat inside the fw-app container.
# Usage: ./scripts/chat.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q '^fw-app$'; then
    echo "fw-app is not running. Start the stack with:"
    echo "  docker compose up -d"
    exit 1
fi

exec docker exec -it fw-app fw-chat chat "$@"

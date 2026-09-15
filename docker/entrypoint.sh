#!/bin/sh
set -eu
: "${SHELLHOUND_TOKEN:?Set SHELLHOUND_TOKEN before starting Shellhound}"
exec shellhound \
  --workspace "${SHELLHOUND_WORKSPACE:-/workspace}" \
  --host 0.0.0.0 \
  --port "${SHELLHOUND_PORT:-8710}" \
  --no-browser \
  --token="$SHELLHOUND_TOKEN" \
  "$@"

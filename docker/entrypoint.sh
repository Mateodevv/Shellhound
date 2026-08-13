#!/bin/sh
# The container's only job: translate environment into the same CLI the
# standalone installation uses. No token, no start -- inside a container the
# bind is never loopback, and server/main.py refuses a non-loopback bind
# without an explicit token. That refusal is the intended behaviour, not a
# defect to paper over here: a team instance whose token nobody chose is a
# team instance nobody controls.
set -eu
exec shellhound \
  --host "${SHELLHOUND_HOST:-0.0.0.0}" \
  --port "${SHELLHOUND_PORT:-8710}" \
  --no-browser \
  ${SHELLHOUND_TOKEN:+--token "${SHELLHOUND_TOKEN}"} \
  "$@"

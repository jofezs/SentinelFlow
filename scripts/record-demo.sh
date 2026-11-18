#!/usr/bin/env bash
# Re-record docs/demo.gif. Needs the Compose stack running (docker compose up -d --wait).
# VHS runs in a container on the Compose network, so the recording shows the real stack.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${SENTINELFLOW_ADMIN_TOKEN:-}" && -f .env ]]; then
  SENTINELFLOW_ADMIN_TOKEN=$(sed -n 's/^SENTINELFLOW_ADMIN_TOKEN=//p' .env | tr -d '\r')
fi
: "${SENTINELFLOW_ADMIN_TOKEN:?set SENTINELFLOW_ADMIN_TOKEN (or put it in .env)}"
export SENTINELFLOW_ADMIN_TOKEN

network=$(docker inspect "$(docker compose ps -q gateway)" \
  --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')

MSYS_NO_PATHCONV=1 docker run --rm \
  --network "$network" \
  -v "$PWD:/vhs" -w /vhs \
  -e SENTINELFLOW_ADMIN_TOKEN \
  -e SENTINELFLOW_URL=http://gateway:8000 \
  -e SENTINELFLOW_RECEIVER_URL=http://webhook-receiver:8080 \
  ghcr.io/charmbracelet/vhs:v0.12.1 docs/demo.tape

echo "wrote docs/demo.gif ($(du -h docs/demo.gif | cut -f1))"

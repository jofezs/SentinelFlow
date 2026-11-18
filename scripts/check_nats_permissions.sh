#!/usr/bin/env bash
# Prove the NATS least-privilege config holds by attacking it with a compromised
# service's real credentials (threat model T7). Runs against the Docker Compose stack.
#
#   scripts/check_nats_permissions.sh
#
# Exits non-zero if any forbidden action succeeds or the allowed control action fails.
set -uo pipefail

cd "$(dirname "$0")/.."
NATS_CONTAINER=$(docker compose ps -q nats)
[[ -n "$NATS_CONTAINER" ]] || { echo "nats is not running (docker compose up first)"; exit 1; }

API="nats://scanner-api:${NATS_PASSWORD_SCANNER_API:-dev-scanner-api}@127.0.0.1:4222"
IMG="nats://scanner-image:${NATS_PASSWORD_SCANNER_IMAGE:-dev-scanner-image}@127.0.0.1:4222"
failures=0

nats_cli() {  # nats_cli <server-url> <args...>   (shares the NATS container's network)
  docker run --rm --network "container:$NATS_CONTAINER" natsio/nats-box:0.17.0 \
    nats --server "$1" "${@:2}" 2>&1
}

expect() {  # expect <description> <regex the output must match> <server> <args...>
  local out
  out=$(nats_cli "${@:3}")
  if grep -qiE "$2" <<<"$out"; then
    printf 'ok    %s\n' "$1"
  else
    printf 'FAIL  %s\n      %s\n' "$1" "$(tr '\n' ' ' <<<"$out" | cut -c1-200)"
    failures=$((failures + 1))
  fi
}

DENIED="permissions violation|authorization violation"
expect "anonymous clients are refused"                   "$DENIED" nats://127.0.0.1:4222 pub policy.evaluated forged
expect "wrong password is refused"                       "$DENIED" nats://scanner-image:guess@127.0.0.1:4222 pub scan.completed.image x
expect "scanner cannot forge a policy decision"          "$DENIED" "$API" pub policy.evaluated forged
expect "scanner cannot forge another scanner's results"  "$DENIED" "$API" pub scan.completed.image forged
expect "scanner cannot request scans"                    "$DENIED" "$API" pub scan.requested.image forged
expect "scanner cannot read the gateway's replies"       "$DENIED" "$API" sub '_INBOX.gateway-worker.>' --count 1 --timeout 2s
expect "scanner cannot delete the stream"                "$DENIED" "$IMG" stream rm SENTINELFLOW -f
# Control: the API scanner may still publish its own results. The payload is not a valid
# event, so the gateway terminates it as malformed.
expect "control: scanner publishes on its own subject"   "Published" "$API" pub scan.completed.api_endpoint '{}'

if (( failures )); then echo "$failures NATS permission check(s) failed"; exit 1; fi
echo "All NATS permission checks passed"

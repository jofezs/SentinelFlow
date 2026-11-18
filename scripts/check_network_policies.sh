#!/usr/bin/env bash
# Verify NetworkPolicy enforcement by opening real TCP connections from inside the pods.
#
#   scripts/check_network_policies.sh [namespace]
#
# Exits non-zero if any allowed path is blocked or any forbidden path is open.
set -uo pipefail

NS=${1:-sentinelflow}
failures=0

# Only Running pods: evicted or terminating ones may still carry the label.
running() { kubectl -n "$NS" get pod -l "app.kubernetes.io/component=$1" --field-selector=status.phase=Running -o jsonpath="{.items[0].$2}"; }
pod_of() { running "$1" metadata.name; }
ip_of()  { running "$1" status.podIP; }

probe() {  # probe <from-component> <host> <port> <CONNECTED|BLOCKED>
  local result
  result=$(kubectl -n "$NS" exec "$(pod_of "$1")" -c "$1" -- python -c "
import socket
try:
    socket.create_connection(('$2', $3), timeout=4).close(); print('CONNECTED')
except Exception:
    print('BLOCKED')" 2>/dev/null)
  if [[ "$result" == "$4" ]]; then
    printf 'ok    %-18s -> %-30s %s\n' "$1" "$2:$3" "$result"
  else
    printf 'FAIL  %-18s -> %-30s %s (expected %s)\n' "$1" "$2:$3" "${result:-error}" "$4"
    failures=$((failures + 1))
  fi
}

echo "== allowed"
probe gateway-worker     sentinelflow-postgres 5432 CONNECTED
probe notifier           sentinelflow-postgres 5432 CONNECTED
probe scanner-api        sentinelflow-nats     4222 CONNECTED
probe scanner-api        example.com            443 CONNECTED

echo "== must be blocked"
probe scanner-api        sentinelflow-postgres 5432 BLOCKED
probe scanner-image      sentinelflow-postgres 5432 BLOCKED
probe gateway            sentinelflow-nats     4222 BLOCKED
probe scanner-api        "$(ip_of gateway)"    8000 BLOCKED
probe scanner-dockerfile example.com            443 BLOCKED
probe gateway-worker     "$(ip_of policy-engine)" 8181 BLOCKED
probe scanner-api        169.254.169.254         80 BLOCKED

if (( failures )); then echo "$failures NetworkPolicy check(s) failed"; exit 1; fi
echo "All NetworkPolicy checks passed"

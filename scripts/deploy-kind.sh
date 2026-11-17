#!/usr/bin/env bash
# Deploy SentinelFlow to a local kind cluster.
#
#   SENTINELFLOW_ADMIN_TOKEN=... scripts/deploy-kind.sh      (token also read from .env)
#
# Idempotent: creates the cluster if missing, (re)builds and loads images, and
# runs `helm upgrade --install`. Works in Git Bash on Windows and on Linux CI.
set -euo pipefail

CLUSTER=sentinelflow
NAMESPACE=sentinelflow
RELEASE=sentinelflow
METRICS_SERVER_VERSION=v0.7.2
IMAGES=(gateway scanner-dockerfile scanner-image scanner-api policy-engine policy-opa webhook-receiver)

cd "$(dirname "$0")/.."

if [[ -z "${SENTINELFLOW_ADMIN_TOKEN:-}" && -f .env ]]; then
  SENTINELFLOW_ADMIN_TOKEN=$(sed -n 's/^SENTINELFLOW_ADMIN_TOKEN=//p' .env | tr -d '\r')
fi
: "${SENTINELFLOW_ADMIN_TOKEN:?set SENTINELFLOW_ADMIN_TOKEN (or put it in .env)}"

step() { printf '\n==> %s\n' "$*"; }

step "Cluster"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --config deploy/kind/cluster.yaml --wait 180s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "metrics-server (needed by the HorizontalPodAutoscalers)"
kubectl apply -f "https://github.com/kubernetes-sigs/metrics-server/releases/download/${METRICS_SERVER_VERSION}/components.yaml" >/dev/null
# kind's kubelets use self-signed certificates; add the flag once.
if ! kubectl -n kube-system get deploy metrics-server -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q kubelet-insecure-tls; then
  kubectl -n kube-system patch deploy metrics-server --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' >/dev/null
fi

step "Build images"
docker compose build --quiet

step "Load images into kind"
for image in "${IMAGES[@]}"; do
  echo "  sentinelflow/${image}:dev"
  kind load docker-image --name "$CLUSTER" "sentinelflow/${image}:dev" >/dev/null
done

step "Namespace (Pod Security Standard: restricted)"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" --overwrite \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted >/dev/null

step "Helm install/upgrade"
helm upgrade --install "$RELEASE" deploy/helm/sentinelflow \
  --namespace "$NAMESPACE" \
  -f deploy/kind/values-kind.yaml \
  --set secrets.adminToken="$SENTINELFLOW_ADMIN_TOKEN" \
  --wait --timeout 10m

step "Helm test"
helm test "$RELEASE" -n "$NAMESPACE"

step "Pods"
kubectl -n "$NAMESPACE" get pods -o wide

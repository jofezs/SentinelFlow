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
# Buildx (0.35, Docker Desktop) mis-resolves Windows Dockerfile paths in its filesystem
# entitlement check and refuses to build files inside this repo. Linux is unaffected.
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  export BUILDX_BAKE_ENTITLEMENTS_FS=0
fi
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
upgrading=false
helm status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1 && upgrading=true
helm upgrade --install "$RELEASE" deploy/helm/sentinelflow \
  --namespace "$NAMESPACE" \
  -f deploy/kind/values-kind.yaml \
  --set secrets.adminToken="$SENTINELFLOW_ADMIN_TOKEN" \
  --wait --timeout 10m

if $upgrading; then
  # Images are rebuilt under the same :dev tag, so the pod specs did not change and
  # Kubernetes kept the old pods. Roll every Deployment onto the freshly loaded images.
  step "Restart pods onto the new images"
  kubectl -n "$NAMESPACE" rollout restart deployment -l "app.kubernetes.io/instance=$RELEASE"
  for d in $(kubectl -n "$NAMESPACE" get deployment -l "app.kubernetes.io/instance=$RELEASE" -o name); do
    kubectl -n "$NAMESPACE" rollout status "$d" --timeout 5m
  done
fi

step "Helm test"
helm test "$RELEASE" -n "$NAMESPACE"

step "Pods"
kubectl -n "$NAMESPACE" get pods -o wide

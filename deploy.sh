#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy.sh — SRE Agent multi-cluster deployment script
#
# Usage:
#   ./deploy.sh                          # deploy to default cluster (jamiat)
#   ./deploy.sh build                    # build + push + deploy (jamiat)
#   ./deploy.sh delete                   # remove from cluster
#
#   CLUSTER=proptech-lite ./deploy.sh          # deploy to proptech-lite cluster
#   CLUSTER=proptech-lite ./deploy.sh build    # build + push + deploy (proptech-lite)
#   CLUSTER=proptech-lite ./deploy.sh delete
#
# ── Cluster profiles ──────────────────────────────────────────────────────────
#
#   jamiat  (default)
#     Registry : jed.ocir.io
#     Tenancy  : ax39qm2olrf8
#     Repo     : jamiat-images
#     ocir-secret source: copy from namespace 'sadan'  (or OCIR_SECRET_SOURCE_NS)
#
#   proptech-lite
#     Registry : me-riyadh-1.ocir.io
#     Tenancy  : axtgrwsd46af
#     Repo     : oke-lite-images
#     ocir-secret: created from env vars OCIR_PASSWORD (+ OCIR_USERNAME optional)
#
#   awqaf
#     Registry : me-riyadh-1.ocir.io
#     Tenancy  : axtgrwsd46af
#     Repo     : proptech-odoo-images
#     ocir-secret: created from env vars OCIR_PASSWORD (+ OCIR_USERNAME optional)
#
#   proptech-prod
#     Registry : me-riyadh-1.ocir.io
#     Tenancy  : axtgrwsd46af
#     Repo     : proptech-odoo-images
#     ocir-secret: created from env vars OCIR_PASSWORD (+ OCIR_USERNAME optional)
#
# ── Env var overrides (all clusters) ─────────────────────────────────────────
#   IMAGE_TAG=sre-agent-v5       override image tag
#   SLACK_WEBHOOK_URL=https://…  set Slack webhook
#
# ── proptech-lite secret creation ─────────────────────────────────────────────
#   OCIR_PASSWORD=<token>        required if ocir-secret doesn't exist yet
#   OCIR_USERNAME=<user>         optional (defaults to axtgrwsd46af/devops@arribatt.com)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

NAMESPACE="sre-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$SCRIPT_DIR/k8s"

# ── Cluster selection ─────────────────────────────────────────────────────────
CLUSTER="${CLUSTER:-jamiat}"

case "$CLUSTER" in
  jamiat)
    OCIR_REGISTRY="jed.ocir.io"
    OCIR_TENANCY="ax39qm2olrf8"
    OCIR_REPO="jamiat-images"
    OCIR_SECRET_MODE="copy"                          # copy from another namespace
    OCIR_SECRET_SOURCE_NS="${OCIR_SECRET_SOURCE_NS:-sadan}"
    ;;
  proptech-lite)
    OCIR_REGISTRY="me-riyadh-1.ocir.io"
    OCIR_TENANCY="axtgrwsd46af"
    OCIR_REPO="oke-lite-images"
    OCIR_SECRET_MODE="create"                        # create from credentials
    OCIR_USERNAME="${OCIR_USERNAME:-axtgrwsd46af/devops@arribatt.com}"
    OCIR_EMAIL="${OCIR_EMAIL:-devops@arribatt.com}"
    ;;
  awqaf)
    OCIR_REGISTRY="me-riyadh-1.ocir.io"
    OCIR_TENANCY="axtgrwsd46af"
    OCIR_REPO="proptech-odoo-images"
    OCIR_SECRET_MODE="create"                        # create from credentials
    OCIR_USERNAME="${OCIR_USERNAME:-axtgrwsd46af/devops@arribatt.com}"
    OCIR_EMAIL="${OCIR_EMAIL:-devops@arribatt.com}"
    ;;
  proptech-prod)
    OCIR_REGISTRY="me-riyadh-1.ocir.io"
    OCIR_TENANCY="axtgrwsd46af"
    OCIR_REPO="proptech-odoo-images"
    OCIR_SECRET_MODE="create"                        # create from credentials
    OCIR_USERNAME="${OCIR_USERNAME:-axtgrwsd46af/devops@arribatt.com}"
    OCIR_EMAIL="${OCIR_EMAIL:-devops@arribatt.com}"
    ;;
  *)
    echo "❌ Unknown cluster: '$CLUSTER'"
    echo "   Valid values: jamiat, proptech-lite, awqaf, proptech-prod"
    exit 1
    ;;
esac

IMAGE_TAG="${IMAGE_TAG:-sre-agent-v5}"
OCIR_IMAGE="${OCIR_REGISTRY}/${OCIR_TENANCY}/${OCIR_REPO}:${IMAGE_TAG}"

echo "┌─────────────────────────────────────────────────────────────────────"
echo "│ Cluster  : $CLUSTER"
echo "│ Image    : $OCIR_IMAGE"
echo "└─────────────────────────────────────────────────────────────────────"

# ── Delete mode ───────────────────────────────────────────────────────────────
if [[ "${1:-}" == "delete" ]]; then
  echo "→ Removing SRE Agent from cluster '$CLUSTER'..."
  kubectl delete namespace "$NAMESPACE" --ignore-not-found
  kubectl delete clusterrole        sre-agent-reader --ignore-not-found
  kubectl delete clusterrolebinding sre-agent-reader --ignore-not-found
  echo "✅ Removed."
  exit 0
fi

# ── Build & push mode ─────────────────────────────────────────────────────────
if [[ "${1:-}" == "build" ]]; then
  echo "→ Building image: $OCIR_IMAGE (linux/amd64)"
  # buildx + --push handles cross-compilation on Apple Silicon (ARM64 host → x86_64 image)
  # and pushes directly to the registry in one step, avoiding a separate docker push.
  # Requires Docker Desktop (QEMU pre-installed). If buildx is missing, run:
  #   docker buildx create --use
  docker buildx build \
    --platform linux/amd64 \
    --push \
    -t "$OCIR_IMAGE" \
    "$SCRIPT_DIR"
  echo "✅ Image pushed: $OCIR_IMAGE"
  echo ""
fi

# ── Patch Slack webhook if provided ──────────────────────────────────────────
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "→ Setting Slack webhook..."
  sed -i.bak "s|https://hooks.slack.com/services/YOUR/WEBHOOK/HERE|${SLACK_WEBHOOK_URL}|g" \
      "$K8S_DIR/03-secret.yaml"
fi

# ── Deploy ────────────────────────────────────────────────────────────────────
echo "→ Deploying to namespace: $NAMESPACE"

kubectl apply -f "$K8S_DIR/00-namespace.yaml"
kubectl apply -f "$K8S_DIR/01-rbac.yaml"
kubectl apply -f "$K8S_DIR/02-configmap-config.yaml"
kubectl apply -f "$K8S_DIR/03-secret.yaml"

# ── OCIR secret ───────────────────────────────────────────────────────────────
echo "→ Setting up ocir-secret in namespace $NAMESPACE..."

if [[ "$OCIR_SECRET_MODE" == "copy" ]]; then
  # Copy from another namespace (jamiat workflow)
  if kubectl get secret ocir-secret -n "$OCIR_SECRET_SOURCE_NS" &>/dev/null; then
    kubectl get secret ocir-secret -n "$OCIR_SECRET_SOURCE_NS" -o json \
      | python3 -c "
import json, sys
s = json.load(sys.stdin)
s['metadata'] = {'name': s['metadata']['name'], 'namespace': '$NAMESPACE'}
print(json.dumps(s))
" | kubectl apply -f -
    echo "✅ ocir-secret copied from namespace '$OCIR_SECRET_SOURCE_NS'"
  else
    echo "⚠️  Could not find ocir-secret in namespace '$OCIR_SECRET_SOURCE_NS'"
    echo "   Run manually: kubectl get secret ocir-secret -n <ns> -o yaml \\"
    echo "     | sed 's/namespace: <ns>/namespace: $NAMESPACE/' | kubectl apply -f -"
  fi

elif [[ "$OCIR_SECRET_MODE" == "create" ]]; then
  # Create from credentials (proptech-lite workflow)
  if kubectl get secret ocir-secret -n "$NAMESPACE" &>/dev/null; then
    echo "✅ ocir-secret already exists in namespace '$NAMESPACE' (skipping creation)"
  else
    if [[ -z "${OCIR_PASSWORD:-}" ]]; then
      echo "❌ OCIR_PASSWORD is required to create ocir-secret for cluster '$CLUSTER'"
      echo "   Run: CLUSTER=$CLUSTER OCIR_PASSWORD='<token>' ./deploy.sh"
      exit 1
    fi
    kubectl create secret docker-registry ocir-secret \
      --namespace="$NAMESPACE" \
      --docker-server="$OCIR_REGISTRY" \
      --docker-username="$OCIR_USERNAME" \
      --docker-password="$OCIR_PASSWORD" \
      --docker-email="$OCIR_EMAIL"
    echo "✅ ocir-secret created for registry '$OCIR_REGISTRY'"
  fi
fi

# ── Apply deployment with the correct image ───────────────────────────────────
# Patch the image inline so we don't have to edit the YAML for every cluster/tag
echo "→ Applying deployment (image: $OCIR_IMAGE)..."
kubectl apply -f "$K8S_DIR/05-deployment.yaml"
kubectl set image deployment/sre-agent \
  sre-agent="$OCIR_IMAGE" \
  -n "$NAMESPACE"

kubectl apply -f "$K8S_DIR/06-service.yaml"
# Note: 07-servicemonitor.yaml is not applied — the v4 agent no longer exposes
# Prometheus /metrics. The web UI is served at / and health at /health.

echo ""
echo "→ Waiting for rollout..."
kubectl rollout status deployment/sre-agent -n "$NAMESPACE" --timeout=120s

echo ""
echo "✅ SRE Agent deployed on cluster: $CLUSTER"
echo ""
echo "── Watch live logs ───────────────────────────────────────────────────────"
echo "   kubectl logs -f deploy/sre-agent -n sre-agent"
echo ""
echo "── Open the web UI dashboard ─────────────────────────────────────────────"
echo "   kubectl port-forward -n sre-agent svc/sre-agent 8080:80"
echo "   then open: http://localhost:8080/"
echo "              http://localhost:8080/health"
echo "              http://localhost:8080/api/status"
echo "              http://localhost:8080/api/node-events?hours=6"
echo ""
echo "── Run an immediate on-demand check ─────────────────────────────────────"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --once"
echo ""
echo "── CLI reports ───────────────────────────────────────────────────────────"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --events"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --incidents"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --odoo"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --odoo --ns awqaf"
echo ""
echo "── Remove the agent ─────────────────────────────────────────────────────"
echo "   CLUSTER=$CLUSTER ./deploy.sh delete"
echo "─────────────────────────────────────────────────────────────────────────"

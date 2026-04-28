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
  *)
    echo "❌ Unknown cluster: '$CLUSTER'"
    echo "   Valid values: jamiat, proptech-lite"
    exit 1
    ;;
esac

IMAGE_TAG="${IMAGE_TAG:-sre-agent-v4}"
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
  echo "→ Building image: $OCIR_IMAGE"
  docker build -t "$OCIR_IMAGE" "$SCRIPT_DIR"

  echo "→ Pushing to OCIR..."
  echo "   (If this fails with 403, run: docker login $OCIR_REGISTRY)"
  docker push "$OCIR_IMAGE"
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

# ── ServiceMonitor (optional — only if Prometheus Operator is running) ────────
if kubectl get crd servicemonitors.monitoring.coreos.com &>/dev/null; then
  echo "→ Applying ServiceMonitor for Prometheus scraping..."
  kubectl apply -f "$K8S_DIR/07-servicemonitor.yaml"
  echo "✅ ServiceMonitor applied."
else
  echo "⚠️  Prometheus Operator CRD not found — skipping ServiceMonitor."
  echo "   If you add kube-prometheus-stack later, run: kubectl apply -f k8s/07-servicemonitor.yaml"
fi

echo ""
echo "→ Waiting for rollout..."
kubectl rollout status deployment/sre-agent -n "$NAMESPACE" --timeout=120s

echo ""
echo "✅ SRE Agent deployed on cluster: $CLUSTER"
echo ""
echo "── Watch live reports ────────────────────────────────────────────────────"
echo "   kubectl logs -f deploy/sre-agent -n sre-agent"
echo ""
echo "── Run an immediate on-demand check ─────────────────────────────────────"
echo "   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --once"
echo ""
echo "── Access Prometheus metrics ─────────────────────────────────────────────"
echo "   kubectl port-forward -n sre-agent svc/sre-agent 8080:80"
echo "   then open: http://localhost:8080/metrics"
echo "            : http://localhost:8080/health"
echo ""
echo "── Deploy process-exporter (Odoo per-worker OS-process visibility) ──────"
echo "   kubectl apply -f k8s/08-process-exporter.yaml"
echo ""
echo "── Import Grafana dashboards ─────────────────────────────────────────────"
echo "   kubectl port-forward -n monitoring svc/prometheus-stack-grafana 3000:80"
echo "   then open: http://localhost:3000  →  Dashboards → Import → Upload JSON"
echo ""
echo "   grafana/sre-dashboard.json                   SRE agent checks & alerts"
echo "   grafana/odoo-dashboard.json                  Odoo workload health"
echo "   grafana/odoo-workers-dashboard.json          Workers — pod-level"
echo "   grafana/odoo-process-workers-dashboard.json  Workers — OS process level"
echo "   grafana/node-storage-dashboard.json          Node disk / PVs / PVCs"
echo "   grafana/events-dashboard.json                K8s Warning Events"
echo ""
echo "── Remove the agent ─────────────────────────────────────────────────────"
echo "   CLUSTER=$CLUSTER ./deploy.sh delete"
echo "─────────────────────────────────────────────────────────────────────────"

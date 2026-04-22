#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy.sh — SRE Agent deployment script
#
# Usage:
#   ./deploy.sh                  # deploy / upgrade (image must already be pushed)
#   ./deploy.sh build            # build + push image to OCIR, then deploy
#   ./deploy.sh delete           # remove everything from the cluster
#
# Prerequisites:
#   - kubectl configured and pointing to your cluster
#   - docker installed (only needed for: ./deploy.sh build)
#   - OCIR credentials (only needed for: ./deploy.sh build)
#
# Set your Slack webhook (optional):
#   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ ./deploy.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

NAMESPACE="sre-agent"
OCIR_IMAGE="jed.ocir.io/ax39qm2olrf8/jamiat-images:sre-agent-v3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$SCRIPT_DIR/k8s"

# ── Delete mode ───────────────────────────────────────────────────────────────
if [[ "${1:-}" == "delete" ]]; then
  echo "→ Removing SRE Agent..."
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
  echo "   (If this fails, run: docker login jed.ocir.io)"
  docker push "$OCIR_IMAGE"
  echo "✅ Image pushed."
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

# ── Copy ocir-secret into sre-agent namespace ─────────────────────────────────
# The agent pulls from the same OCIR registry as your Odoo images.
# We copy the existing ocir-secret from the 'sadan' namespace.
echo "→ Copying ocir-secret into namespace $NAMESPACE..."
SOURCE_NS="${OCIR_SECRET_SOURCE_NS:-sadan}"
if kubectl get secret ocir-secret -n "$SOURCE_NS" &>/dev/null; then
  kubectl get secret ocir-secret -n "$SOURCE_NS" -o json \
    | python3 -c "
import json, sys
s = json.load(sys.stdin)
s['metadata'] = {'name': s['metadata']['name'], 'namespace': '$NAMESPACE'}
print(json.dumps(s))
" | kubectl apply -f -
  echo "✅ ocir-secret copied from $SOURCE_NS"
else
  echo "⚠️  Could not find ocir-secret in namespace $SOURCE_NS"
  echo "   Run manually: kubectl get secret ocir-secret -n <ns> -o yaml | sed 's/namespace: <ns>/namespace: $NAMESPACE/' | kubectl apply -f -"
fi

# ── Apply deployment and service ──────────────────────────────────────────────
kubectl apply -f "$K8S_DIR/05-deployment.yaml"
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
echo "✅ SRE Agent deployed!"
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
echo "── Import Grafana dashboard ──────────────────────────────────────────────"
echo "   kubectl port-forward -n monitoring svc/prometheus-stack-grafana 3000:80"
echo "   then open: http://localhost:3000"
echo "   Dashboards → Import → Upload JSON → grafana/sre-dashboard.json"
echo ""
echo "── Remove the agent ─────────────────────────────────────────────────────"
echo "   ./deploy.sh delete"
echo "─────────────────────────────────────────────────────────────────────────"

#!/usr/bin/env python3
"""
SRE Agent v3 — Kubernetes Cluster Health Monitor
Prometheus /metrics + Slack alerting + CLI output.

Run modes:
  python agent.py            # continuous loop (default)
  python agent.py --once     # run once, print, exit

Endpoints (port 8080):
  /metrics   — Prometheus text exposition (scraped by kube-prometheus-stack)
  /health    — Simple JSON health check (used by Kubernetes liveness probe)

Checks:
  Nodes        — Ready/NotReady, DiskPressure, MemoryPressure, PIDPressure
  Pods         — Evicted, CrashLoopBackOff, OOMKilled, Pending, high restarts,
                 ContainerStatusUnknown, dead pods not cleaned up
  Events       — All Warning-type K8s events (last N hours) — cluster history
  PVCs         — Lost / Pending (stuck) PersistentVolumeClaims
  DaemonSets   — Not fully rolled out
  StatefulSets — Not fully ready
  Jobs         — Failed Kubernetes Jobs
  Services     — Services with no ready endpoints (broken selector)
  Deployments  — imagePullPolicy:Always, no ephemeral-storage limit,
                 high revisionHistoryLimit, no resource requests
  ReplicaSets  — Old 0/0/0 RSes pinning image layers on disk
  Resources    — Memory/CPU limit overcommit per node
"""

import gc
import sys
import os
import time
import logging
import threading
import http.server
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException

try:
    from prometheus_client import (
        Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, REGISTRY,
    )
    PROMETHEUS_ENABLED = True
except ImportError:
    PROMETHEUS_ENABLED = False

# ── Config ────────────────────────────────────────────────────────────────────
CLUSTER_NAME         = os.getenv("CLUSTER_NAME",              "k8s-cluster")
SLACK_WEBHOOK_URL    = os.getenv("SLACK_WEBHOOK_URL",         "")
CHECK_INTERVAL       = int(os.getenv("CHECK_INTERVAL_SECONDS","300"))
HTTP_PORT            = int(os.getenv("HTTP_PORT",             "8080"))
RESTART_THRESHOLD    = int(os.getenv("RESTART_THRESHOLD",     "5"))
PENDING_MINUTES      = int(os.getenv("PENDING_THRESHOLD_MINUTES", "10"))
OLD_RS_DAYS          = int(os.getenv("OLD_RS_THRESHOLD_DAYS", "3"))
OLD_FAILED_POD_HOURS = int(os.getenv("OLD_FAILED_POD_HOURS",  "2"))
OVERCOMMIT_WARN_PCT  = int(os.getenv("OVERCOMMIT_WARN_PERCENT","120"))
EVENTS_LOOKBACK_H    = int(os.getenv("EVENTS_LOOKBACK_HOURS", "2"))

SKIP_NS = {
    "kube-system","cert-manager","monitoring",
    "ingress-nginx","nfs","kube-public","kube-node-lease",
}

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")

# ── ANSI Colors (no external deps) ───────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() or os.getenv("FORCE_COLOR", "")
R  = "\033[91m"   if USE_COLOR else ""
Y  = "\033[93m"   if USE_COLOR else ""
G  = "\033[92m"   if USE_COLOR else ""
B  = "\033[94m"   if USE_COLOR else ""
C  = "\033[96m"   if USE_COLOR else ""
DM = "\033[2m"    if USE_COLOR else ""
BD = "\033[1m"    if USE_COLOR else ""
W  = "\033[97m"   if USE_COLOR else ""
RS = "\033[0m"    if USE_COLOR else ""

W72 = 72

def _line(char="─", width=W72): return char * width
def _head(title, char="━"): return f"\n{BD}{_line(char)}{RS}\n {W}{title}{RS}\n{BD}{_line(char)}{RS}"
def _dim(s):  return f"{DM}{s}{RS}"
def _bold(s): return f"{BD}{s}{RS}"


# ╔══════════════════════════════════════════════════════════════════╗
# ║  RECOMMENDATIONS                                                  ║
# ╚══════════════════════════════════════════════════════════════════╝
# Each entry: { root_cause, immediate, prevent }
# Keyed by the check name produced by _issue(..., check=<key>, ...)

_REC: Dict[str, Dict[str, str]] = {
    "NodeNotReady": {
        "root_cause": "Node lost connectivity to the control plane, or a system daemon "
                      "(kubelet/CRI-O/containerd) crashed. Can also be triggered by disk or memory exhaustion.",
        "immediate":  "SSH to node → systemctl status kubelet; journalctl -u kubelet -n 50. "
                      "Restart if needed: systemctl restart kubelet",
        "prevent":    "Enable OKE node auto-repair. Deploy Node Problem Detector DaemonSet. "
                      "Monitor system resources with node-level alerts in Prometheus.",
    },
    "NodeDiskPressure": {
        "root_cause": "Kubelet detected free disk on ephemeral storage dropped below the eviction "
                      "threshold (~1 GiB / 10%). Primary drivers: accumulated container image layers "
                      "from imagePullPolicy:Always + many old 0/0/0 ReplicaSets holding references, "
                      "and containers with no ephemeral-storage limit writing large logs or temp files.",
        "immediate":  "On affected node: crictl rmi --prune (removes unreferenced images). "
                      "Delete old 0/0/0 RSes: kubectl get rs -A | awk 'NR>1&&$3==0&&$4==0{print $1,$2}'. "
                      "Delete evicted pods: kubectl delete pods -A --field-selector=status.phase=Failed",
        "prevent":    "Set imagePullPolicy: IfNotPresent on all deployments. "
                      "Set revisionHistoryLimit: 2. "
                      "Add resources.limits.ephemeral-storage to every container. "
                      "Configure kubelet --image-gc-high-threshold and --image-gc-low-threshold.",
    },
    "NodeMemoryPressure": {
        "root_cause": "Total memory used on the node exceeds the kubelet eviction threshold. "
                      "Pods with no memory limits are the most likely cause — they can expand unbounded.",
        "immediate":  "kubectl top pods --all-namespaces --sort-by=memory to find the biggest consumer. "
                      "Kill or restart the top offender to relieve pressure immediately.",
        "prevent":    "Set memory limits on all containers. Use VPA to auto-tune limits. "
                      "Set memory requests so the scheduler distributes pods evenly across nodes.",
    },
    "NodePIDPressure": {
        "root_cause": "The node is running out of process IDs. Usually caused by a runaway process "
                      "forking excessively (fork bomb, misconfigured Java thread pool, etc.).",
        "immediate":  "SSH to node → ps aux | wc -l to confirm. Identify the container: "
                      "crictl ps + crictl exec to check pid counts per container.",
        "prevent":    "Set PID limits per pod via pod security context. Configure kubelet "
                      "--pod-max-pids. Investigate applications that fork heavily.",
    },
    "PodEvicted": {
        "root_cause": "Pod was forcibly terminated by kubelet due to resource pressure — most commonly "
                      "DiskPressure (ephemeral-storage) or MemoryPressure. The eviction message in "
                      "pod.status.message contains the exact reason.",
        "immediate":  "kubectl delete pod <pod> -n <ns> to remove the dead artifact. "
                      "kubectl describe node <node> to see current pressure conditions. "
                      "If DiskPressure: crictl rmi --prune on the affected node.",
        "prevent":    "Add ephemeral-storage limits to all containers. "
                      "Set imagePullPolicy: IfNotPresent. Set revisionHistoryLimit: 2. "
                      "Add PodDisruptionBudget to protect critical workloads.",
    },
    "OOMKilled": {
        "root_cause": "Container exceeded its memory limit and was killed by the Linux OOM killer. "
                      "The process was consuming more memory than resources.limits.memory allowed.",
        "immediate":  "kubectl top pod <pod> -n <ns> to see current usage. "
                      "kubectl logs <pod> -n <ns> --previous to see what ran before death. "
                      "Temporarily increase memory limit to restore service.",
        "prevent":    "Raise memory limit. Use VPA (VerticalPodAutoscaler) to auto-tune. "
                      "Profile the application for memory leaks. "
                      "For JVM: set -Xmx below the container limit (e.g. limit 1Gi → -Xmx768m). "
                      "For Node.js: set --max-old-space-size below limit.",
    },
    "CrashLoopBackOff": {
        "root_cause": "Container is starting, crashing, and being restarted in a loop. "
                      "Common causes: bad config / missing environment variable / missing secret, "
                      "dependency not ready (DB connection refused), or application startup exception.",
        "immediate":  "kubectl logs <pod> -n <ns> --previous to see crash output. "
                      "kubectl describe pod <pod> -n <ns> to see exit codes and events. "
                      "Exit code 1 = app error; 137 = OOMKill; 143 = SIGTERM (probe killed it).",
        "prevent":    "Add readinessProbe so traffic doesn't reach an unready pod. "
                      "Use init containers to wait for DB/cache before main container starts. "
                      "Validate all required env vars at startup with clear error messages.",
    },
    "ImagePullBackOff": {
        "root_cause": "Kubernetes cannot pull the container image. Causes: (1) image tag doesn't exist, "
                      "(2) registry rate limit hit (Docker Hub free = 100 pulls/6h per IP), "
                      "(3) missing or expired imagePullSecret, (4) private registry unreachable.",
        "immediate":  "kubectl describe pod <pod> -n <ns> for exact error. "
                      "Verify the image: docker manifest inspect <image>. "
                      "Check imagePullSecret: kubectl get secret ocir-secret -n <ns>.",
        "prevent":    "Push all images to your private registry (OCIR). "
                      "Set imagePullPolicy: IfNotPresent. "
                      "Use image digests (sha256) instead of mutable tags in production. "
                      "Rotate imagePullSecrets before expiry (set up automated rotation).",
    },
    "ErrImagePull": {
        "root_cause": "First-time image pull failure — same root causes as ImagePullBackOff. "
                      "This transitions to ImagePullBackOff after repeated failures.",
        "immediate":  "kubectl describe pod <pod> -n <ns> for the exact registry error.",
        "prevent":    "Same as ImagePullBackOff prevention.",
    },
    "PodPendingTooLong": {
        "root_cause": "Scheduler cannot place the pod on any node. Common causes: "
                      "(1) insufficient CPU/memory on all nodes, "
                      "(2) nodeSelector / affinity rules matching no node, "
                      "(3) PVC not bound (waiting for storage provisioner), "
                      "(4) taint/toleration mismatch.",
        "immediate":  "kubectl describe pod <pod> -n <ns> → Events section shows 'FailedScheduling'. "
                      "kubectl top nodes to check available resources. "
                      "kubectl get pvc -n <ns> to check if storage is the blocker.",
        "prevent":    "Set accurate resource requests (not artificially high). "
                      "Use Cluster Autoscaler to add nodes on demand. "
                      "Audit nodeSelector labels match actual node labels.",
    },
    "HighRestartCount": {
        "root_cause": "Container has restarted many times — recurring failure. "
                      "Could be OOMKills (exit 137), application crashes (exit 1), "
                      "liveness probe too aggressive, or a bad rolling-restart loop.",
        "immediate":  "kubectl logs <pod> -n <ns> --previous to see crash. "
                      "Exit code 137 → OOM (increase limit). "
                      "Exit code 1 → application error (check logs). "
                      "Exit code 143 → probe killed it (tune probe thresholds).",
        "prevent":    "Fix the root crash cause. Tune liveness probe "
                      "(increase failureThreshold and initialDelaySeconds). "
                      "Use VPA for memory sizing. Add proper health checks in the application.",
    },
    "DeadPodNotCleaned": {
        "root_cause": "A failed pod has been sitting on the node for too long. "
                      "Terminated pods still consume ephemeral-storage (log files, overlay layers) "
                      "until manually deleted or garbage-collected.",
        "immediate":  "kubectl delete pod <pod> -n <ns>. "
                      "For bulk cleanup: kubectl delete pods -A --field-selector=status.phase=Failed",
        "prevent":    "Add a CronJob or use ttlSecondsAfterFinished on Jobs. "
                      "Kubernetes 1.23+ has automatic pod GC (--terminated-pod-gc-threshold on controller-manager).",
    },
    "ContainerStatusUnknown": {
        "root_cause": "Container is in Unknown state — the node that ran it became unreachable and "
                      "kubelet could not report the final status. The pod is effectively orphaned.",
        "immediate":  "kubectl delete pod <pod> -n <ns> --grace-period=0 --force. "
                      "Check the node it ran on: kubectl get events -n <ns> --sort-by=.lastTimestamp",
        "prevent":    "Enable node auto-repair to quickly replace failed nodes. "
                      "Use multiple replicas so Unknown pods don't affect availability.",
    },
    "PVCLost": {
        "root_cause": "The PersistentVolume backing this PVC was deleted or is no longer accessible. "
                      "Any pod trying to mount it will fail to start.",
        "immediate":  "kubectl describe pvc <name> -n <ns>. "
                      "Check underlying block volume in OCI console. "
                      "If data is recoverable: create new PV/PVC, restore from backup.",
        "prevent":    "Never delete PVs manually. Use StorageClass with reclaimPolicy: Retain "
                      "for production workloads. Implement regular backups with Velero or OCI Block Volume snapshots.",
    },
    "PVCPending": {
        "root_cause": "PVC is waiting for a PersistentVolume to be provisioned. "
                      "Causes: StorageClass not configured, volume quota exceeded, "
                      "provisioner pod not running, or wrong availability zone.",
        "immediate":  "kubectl describe pvc <name> -n <ns> → Events for provisioner errors. "
                      "kubectl get storageclass to check available classes. "
                      "kubectl get pods -n kube-system | grep provisioner",
        "prevent":    "Pre-provision volumes for stateful workloads. "
                      "Monitor storage quota. Use WaitForFirstConsumer binding mode for zone-aware provisioning.",
    },
    "ServiceNoEndpoints": {
        "root_cause": "The Service selector labels don't match any running pod labels, "
                      "or all matching pods are failing their readinessProbe. "
                      "Traffic to this service returns 'connection refused'.",
        "immediate":  "kubectl get pods -n <ns> -l <selector> to check matching pods. "
                      "kubectl describe endpoints <svc> -n <ns>. "
                      "Compare Service spec.selector vs pod metadata.labels.",
        "prevent":    "Use consistent label conventions. Test selectors before applying. "
                      "Add readinessProbes so only healthy pods receive traffic.",
    },
    "OldReplicaSets": {
        "root_cause": "Kubernetes keeps old ReplicaSet objects as rollback history. Each RS holds "
                      "references to its image, preventing container runtime GC from removing those "
                      "layers. With imagePullPolicy:Always and many deployments, this accumulates "
                      "GBs of dead image layers on every node.",
        "immediate":  "kubectl get rs -n <ns> | awk 'NR>1&&$2==0&&$3==0{print $1}' | "
                      "xargs kubectl delete rs -n <ns>. Then on nodes: crictl rmi --prune",
        "prevent":    "Set revisionHistoryLimit: 2 on all deployments (keeps current + 1 rollback). "
                      "Set imagePullPolicy: IfNotPresent. "
                      "Automate RS cleanup with a weekly CronJob or admission webhook.",
    },
    "ImagePullPolicyAlways": {
        "root_cause": "imagePullPolicy:Always forces a registry check and potential re-pull on every "
                      "pod start, even if the image is cached locally. This causes extra network traffic, "
                      "slower cold starts, and accumulation of image layers because old layers aren't "
                      "immediately GC'd (kubelet waits for imageMinimumGCAge, default 2 minutes).",
        "immediate":  "Change to IfNotPresent in the deployment spec. Safe as long as "
                      "you use unique immutable image tags per build (not :latest).",
        "prevent":    "Always use content-addressable tags (git SHA or semver) — never :latest in production. "
                      "Set imagePullPolicy: IfNotPresent as the org-wide default.",
    },
    "NoEphemeralStorageLimit": {
        "root_cause": "Without an ephemeral-storage limit, a single container can fill the node's "
                      "entire disk with logs, temp files, or application data. When the node's disk "
                      "fills up, kubelet evicts ALL pods on the node — not just the offending one.",
        "immediate":  "Add resources.limits.ephemeral-storage: 1Gi to the container spec "
                      "(adjust based on actual log/temp file needs).",
        "prevent":    "Enforce via LimitRange with a default ephemeral-storage limit in each namespace. "
                      "Configure log rotation in the application (max size, max files). "
                      "Use a log aggregation sidecar (fluentd/Promtail) to ship logs to Loki/Elasticsearch.",
    },
    "HighRevisionHistory": {
        "root_cause": "A high revisionHistoryLimit keeps many old ReplicaSets around, each "
                      "pinning image layers on every node disk. The default is 10 — far more than needed.",
        "immediate":  "kubectl patch deploy <name> -n <ns> --type=json "
                      "-p='[{\"op\":\"replace\",\"path\":\"/spec/revisionHistoryLimit\",\"value\":2}]'",
        "prevent":    "Set revisionHistoryLimit: 2 in all deployment templates. "
                      "Enforce via OPA/Kyverno policy.",
    },
    "NoPodRequests": {
        "root_cause": "Pods without resource requests are 'BestEffort' QoS class — the scheduler "
                      "places them without resource consideration and they are evicted FIRST under "
                      "pressure (before Burstable, before Guaranteed).",
        "immediate":  "Add resource requests (even small: cpu: 10m, memory: 64Mi) to make "
                      "the pod Burstable QoS and improve scheduling decisions.",
        "prevent":    "Enforce via LimitRange with default requests in each namespace. "
                      "Use VPA in recommendation mode to suggest values based on actual usage.",
    },
    "MemLimitOvercommit": {
        "root_cause": "Total memory limits of all pods exceed the node's allocatable memory. "
                      "If all pods hit their limits simultaneously, the Linux OOM killer activates "
                      "and starts terminating containers — causing cascading pod failures.",
        "immediate":  "kubectl top pods --all-namespaces --sort-by=memory to find top consumers. "
                      "Consider moving workloads to other nodes via pod affinity/anti-affinity.",
        "prevent":    "Set limits conservatively (≤ 2× requests). "
                      "Use VPA to auto-tune. "
                      "Add more nodes or use larger node shapes for memory-intensive workloads.",
    },
    "CPULimitOvercommit": {
        "root_cause": "Total CPU limits exceed node allocatable CPU. Unlike memory, this causes "
                      "CPU throttling (not eviction), which degrades response times for all pods.",
        "immediate":  "kubectl top pods --all-namespaces --sort-by=cpu to find top consumers.",
        "prevent":    "Set CPU limits equal to requests for predictable performance. "
                      "For latency-sensitive services, prefer more nodes over fewer large ones.",
    },
    "JobFailed": {
        "root_cause": "A Kubernetes Job has one or more failed attempts. The job may still be retrying "
                      "up to its backoffLimit. CronJob children will keep creating new jobs on schedule.",
        "immediate":  "kubectl logs -l job-name=<name> -n <ns> --tail=100 to see failure output. "
                      "kubectl describe job <name> -n <ns> to check backoff status.",
        "prevent":    "Add proper error handling and retry logic in the job code. "
                      "Set appropriate backoffLimit. "
                      "Use activeDeadlineSeconds to prevent jobs from hanging forever.",
    },
    "DaemonSetNotReady": {
        "root_cause": "One or more nodes are missing a ready DaemonSet pod. Causes: "
                      "node taint without matching toleration, insufficient node resources, "
                      "or the pod itself is failing to start.",
        "immediate":  "kubectl rollout status ds/<name> -n <ns>. "
                      "kubectl get pods -n <ns> -l <ds-selector> -o wide to see which nodes are affected.",
        "prevent":    "Ensure DaemonSet tolerations cover all node taints. "
                      "Set appropriate resource requests. "
                      "Test DaemonSet on all node shapes before production rollout.",
    },
    "StatefulSetNotReady": {
        "root_cause": "One or more StatefulSet pods are not ready. StatefulSets upgrade sequentially — "
                      "a single failing pod blocks the entire rollout. Common cause: PVC provisioning "
                      "failure, missing config, or application startup issue.",
        "immediate":  "kubectl get pods -n <ns> -l <sts-selector> to identify failing pods. "
                      "kubectl describe pod <pod> to see Events. "
                      "StatefulSets wait for each pod to be Ready before proceeding to the next.",
        "prevent":    "Ensure persistent storage is provisioned before pod starts. "
                      "Use proper readinessProbe that accurately reflects app readiness. "
                      "Test the startup sequence on staging before production.",
    },
}


# ╔══════════════════════════════════════════════════════════════════╗
# ║  PROMETHEUS METRICS                                              ║
# ╚══════════════════════════════════════════════════════════════════╝

if PROMETHEUS_ENABLED:
    # ── Summary gauges (updated every cycle) ────────────────────────────────
    _g_critical    = Gauge('sre_critical_issues_total',    'Current CRITICAL issues count')
    _g_warning     = Gauge('sre_warning_issues_total',     'Current WARNING issues count')
    _g_info        = Gauge('sre_info_issues_total',        'Current INFO issues count')
    _g_healthy     = Gauge('sre_cluster_healthy',          '1 = no critical issues, 0 = critical issues present')
    _g_nodes       = Gauge('sre_nodes_total',              'Total nodes in cluster')
    _g_nodes_ready = Gauge('sre_nodes_ready',              'Nodes in Ready state')
    _g_last_check  = Gauge('sre_last_check_timestamp_seconds', 'Unix timestamp of last completed check cycle')
    _g_duration    = Gauge('sre_check_duration_seconds',   'Duration of last check cycle in seconds')

    # ── Per-check breakdown (bounded cardinality) ────────────────────────────
    # One time-series per (severity, check_name) pair — grows as new check types appear
    _g_by_check    = Gauge('sre_issues_by_check',
                           'Active issue count by severity and check type',
                           ['severity', 'check'])

    # ── Event counters (cumulative — use rate() / increase() in Grafana) ───
    # Only incremented when a NEW issue appears (not every cycle for persistent ones)
    _c_evictions   = Counter('sre_evictions_detected_total',   'New Evicted pods detected across all cycles')
    _c_oomkills    = Counter('sre_oomkills_detected_total',    'New OOMKilled containers detected')
    _c_crashloops  = Counter('sre_crashloops_detected_total',  'New CrashLoopBackOff pods detected')
    _c_checks_run  = Counter('sre_check_cycles_total',         'Total check cycles completed')

    # ── Static recommendation info metric (populated once at startup) ────────
    # Labels carry the recommendation text for each check type.
    # Join this with sre_issues_by_check in Grafana to show recommendations
    # alongside active issues — just like the CLI output.
    #
    # PromQL to use in Grafana:
    #   (sre_issues_by_check > 0) * on(check) group_left(root_cause,immediate,prevent) sre_check_rec_info
    #
    _g_rec_info = Gauge('sre_check_rec_info',
                        'Static recommendation text per check type. '
                        'Join with sre_issues_by_check on (check) to display in tables.',
                        ['check', 'root_cause', 'immediate', 'prevent'])

    def _setup_rec_metrics():
        """Populate sre_check_rec_info once at process startup — static, never changes."""
        for chk, rec in _REC.items():
            _g_rec_info.labels(
                check=chk,
                root_cause=rec['root_cause'][:220],
                immediate=rec['immediate'][:220],
                prevent=rec['prevent'][:220],
            ).set(1)

    # ── State for deduplicating counter increments ───────────────────────────
    _prev_issue_keys: Set[Tuple[str, str]] = set()
    _seen_check_labels: Set[Tuple[str, str]] = set()

    def update_metrics(report: Dict[str, Any], duration: float) -> None:
        """Update all Prometheus metrics from the latest report."""
        global _prev_issue_keys, _seen_check_labels

        s = report["summary"]
        _g_critical.set(s["critical"])
        _g_warning.set(s["warning"])
        _g_info.set(s["info"])
        _g_healthy.set(1 if report["healthy"] else 0)
        _g_nodes.set(len(report["nodes_overview"]))
        _g_nodes_ready.set(sum(1 for n in report["nodes_overview"] if n["ready"]))
        _g_last_check.set(time.time())
        _g_duration.set(duration)
        _c_checks_run.inc()

        # Rebuild per-check counts and new-issue counters
        counts: Dict[Tuple[str, str], int] = {}
        current_keys: Set[Tuple[str, str]] = set()

        for issue in report["issues"]:
            label_key = (issue["severity"], issue["check"])
            counts[label_key] = counts.get(label_key, 0) + 1

            resource_key = (issue["check"], issue["resource"])
            current_keys.add(resource_key)

            # Only count genuinely new issues (not persistent ones from prior cycles)
            if resource_key not in _prev_issue_keys:
                chk = issue["check"]
                if chk == "PodEvicted":
                    _c_evictions.inc()
                elif chk == "OOMKilled":
                    _c_oomkills.inc()
                elif chk == "CrashLoopBackOff":
                    _c_crashloops.inc()

        # Set NEW counts FIRST — no zero-window for active issues during Prometheus scrape
        new_check_labels: Set[Tuple[str, str]] = set()
        for (sev, chk), cnt in counts.items():
            _g_by_check.labels(severity=sev, check=chk).set(cnt)
            new_check_labels.add((sev, chk))

        # THEN zero out only labels that are no longer active this cycle
        for sev, chk in _seen_check_labels - new_check_labels:
            _g_by_check.labels(severity=sev, check=chk).set(0)

        _seen_check_labels = new_check_labels
        _prev_issue_keys = current_keys

    def _noop_setup():
        pass

else:
    def update_metrics(report: Dict[str, Any], duration: float) -> None:
        pass  # no-op if prometheus_client not installed
    def _setup_rec_metrics():
        pass


# ╔══════════════════════════════════════════════════════════════════╗
# ║  HTTP SERVER  (/metrics  +  /health)                             ║
# ╚══════════════════════════════════════════════════════════════════╝

_agent_start_time = time.time()
_last_report: Dict[str, Any] = {}
_last_report_lock = threading.Lock()


class _MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            if PROMETHEUS_ENABLED:
                output = generate_latest()
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                self.end_headers()
                self.wfile.write(output)
            else:
                body = b"# prometheus_client not installed\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

        elif self.path in ("/health", "/healthz", "/"):
            with _last_report_lock:
                healthy = _last_report.get("healthy", True)
                ts      = _last_report.get("checked_at", "")
            body = (
                f'{{"status":"ok","cluster":"{CLUSTER_NAME}",'
                f'"healthy":{str(healthy).lower()},'
                f'"checked_at":"{ts}"}}'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress per-request access logs to reduce noise


def start_metrics_server():
    """Start the HTTP server in a daemon thread."""
    server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), _MetricsHandler)
    t = threading.Thread(target=server.serve_forever, name="metrics-http", daemon=True)
    t.start()
    print(
        f"[{_now().strftime('%Y-%m-%d %H:%M:%S UTC')}] "
        f"📡 Metrics server listening on :{HTTP_PORT}  "
        f"  /metrics  /health"
    )
    return server


# ╔══════════════════════════════════════════════════════════════════╗
# ║  K8S HELPERS                                                     ║
# ╚══════════════════════════════════════════════════════════════════╝

def _clients() -> Tuple:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return (
        client.CoreV1Api(),
        client.AppsV1Api(),
        client.BatchV1Api(),
    )

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _age(dt) -> str:
    if dt is None: return "?"
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    d = _now() - dt
    dy, s = d.days, d.seconds
    if dy > 1:  return f"{dy}d"
    if dy == 1: return f"1d{s//3600}h"
    if s >= 3600: return f"{s//3600}h{(s%3600)//60}m"
    return f"{s//60}m"

def _ts_full(dt) -> str:
    if not dt: return "?"
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def _issue(sev, check, ns_name, msg, when=None, age=None, action=None) -> Dict:
    i = {"severity": sev, "check": check, "resource": ns_name, "message": msg}
    if when is not None:
        i["ts"]  = _ts_full(when)
        i["age"] = _age(when)
    elif age:
        i["age"] = age
    if action:
        i["action"] = action
    return i

def _cpu(v) -> int:
    v = str(v or "0").strip()
    if v.endswith("m"): return int(v[:-1])
    try:    return int(float(v) * 1000)
    except: return 0

def _mem(v) -> int:
    v = str(v or "0").strip()
    try:
        if v.endswith("Ki"): return int(v[:-2]) // 1024
        if v.endswith("Mi"): return int(v[:-2])
        if v.endswith("Gi"): return int(v[:-2]) * 1024
        if v.endswith("Ti"): return int(v[:-2]) * 1024 * 1024
        if v.endswith("K") or v.endswith("k"): return int(v[:-1]) // 1024
        if v.endswith("M"): return int(v[:-1])
        if v.endswith("G"): return int(v[:-1]) * 1024
        return int(v) // (1024 * 1024)
    except: return 0


# ╔══════════════════════════════════════════════════════════════════╗
# ║  CHECKS                                                          ║
# ╚══════════════════════════════════════════════════════════════════╝

def node_overview(node_items: list) -> List[Dict]:
    rows = []
    for node in node_items:
        name    = node.metadata.name
        alloc   = node.status.allocatable or {}
        created = node.metadata.creation_timestamp
        conditions = {c.type: c.status for c in (node.status.conditions or [])}
        ready    = conditions.get("Ready") == "True"
        disk_p   = conditions.get("DiskPressure") == "True"
        mem_p    = conditions.get("MemoryPressure") == "True"
        pid_p    = conditions.get("PIDPressure") == "True"
        flags = []
        if disk_p: flags.append(f"{R}DiskPressure{RS}")
        if mem_p:  flags.append(f"{R}MemPressure{RS}")
        if pid_p:  flags.append(f"{Y}PIDPressure{RS}")
        rows.append({
            "name":   name,
            "ready":  ready,
            "flags":  flags,
            "cpu_m":  _cpu(alloc.get("cpu", "0")),
            "mem_mi": _mem(alloc.get("memory", "0")),
            "age":    _age(created),
        })
    return rows


def check_nodes(node_items: list) -> List[Dict]:
    issues = []
    for node in node_items:
        n = node.metadata.name
        for c in (node.status.conditions or []):
            if c.type == "Ready" and c.status != "True":
                issues.append(_issue("CRITICAL", "NodeNotReady", f"node/{n}",
                    f"Node is NOT READY — {(c.message or c.reason or '')[:100]}",
                    action=f"kubectl describe node {n}"))
            if c.type == "DiskPressure" and c.status == "True":
                issues.append(_issue("CRITICAL", "NodeDiskPressure", f"node/{n}",
                    "Active DISK PRESSURE — pods are being evicted right now",
                    action=f"On node: crictl rmi --prune && crictl rm $(crictl ps -a --state exited -q)"))
            if c.type == "MemoryPressure" and c.status == "True":
                issues.append(_issue("CRITICAL", "NodeMemoryPressure", f"node/{n}",
                    "Active MEMORY PRESSURE",
                    action=f"kubectl top pods --all-namespaces --sort-by=memory"))
            if c.type == "PIDPressure" and c.status == "True":
                issues.append(_issue("WARNING", "NodePIDPressure", f"node/{n}",
                    "Active PID PRESSURE"))
    return issues


def check_pods(pod_items: list) -> List[Dict]:
    issues = []
    old_fail = _now() - timedelta(hours=OLD_FAILED_POD_HOURS)
    old_pend = _now() - timedelta(minutes=PENDING_MINUTES)

    for pod in pod_items:
        ns, name = pod.metadata.namespace, pod.metadata.name
        phase    = pod.status.phase or ""
        reason   = pod.status.reason or ""
        created  = pod.metadata.creation_timestamp

        if phase == "Failed" and reason == "Evicted":
            msg = (pod.status.message or "")[:200]
            issues.append(_issue("CRITICAL", "PodEvicted", f"{ns}/{name}", msg,
                when=created, action=f"kubectl delete pod {name} -n {ns}"))
            continue

        if phase == "Failed":
            if created and created.replace(tzinfo=timezone.utc) < old_fail:
                issues.append(_issue("WARNING", "DeadPodNotCleaned", f"{ns}/{name}",
                    f"Failed pod sitting for {_age(created)} — disk artifact on node",
                    when=created, action=f"kubectl delete pod {name} -n {ns}"))
            continue

        if phase == "Pending":
            if created and created.replace(tzinfo=timezone.utc) < old_pend:
                issues.append(_issue("WARNING", "PodPendingTooLong", f"{ns}/{name}",
                    f"Stuck Pending for {_age(created)} — check resources / nodeSelector / PVC / image",
                    when=created, action=f"kubectl describe pod {name} -n {ns}"))
            continue

        for cs in (pod.status.container_statuses or []):
            cn = cs.name

            if cs.state and cs.state.waiting:
                wr = cs.state.waiting.reason or ""
                if wr in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"):
                    issues.append(_issue("CRITICAL", wr, f"{ns}/{name}",
                        f"Container '{cn}' — {cs.state.waiting.message or wr}",
                        when=created,
                        action=f"kubectl logs {name} -n {ns} -c {cn} --previous"))

            if cs.state and cs.state.terminated:
                if (cs.state.terminated.reason or "") == "ContainerStatusUnknown":
                    issues.append(_issue("WARNING", "ContainerStatusUnknown", f"{ns}/{name}",
                        f"Container '{cn}' Unknown state — orphaned after node failure",
                        when=created,
                        action=f"kubectl delete pod {name} -n {ns} --grace-period=0 --force"))

            if cs.last_state and cs.last_state.terminated:
                if cs.last_state.terminated.reason == "OOMKilled":
                    limit_mem = ""
                    for c in (pod.spec.containers or []):
                        if c.name == cn and c.resources and c.resources.limits:
                            m = c.resources.limits.get("memory", "")
                            if m: limit_mem = f" (current limit: {m})"
                    issues.append(_issue("CRITICAL", "OOMKilled", f"{ns}/{name}",
                        f"Container '{cn}' was OOMKilled{limit_mem} — increase memory limit",
                        when=created,
                        action=f"kubectl top pod {name} -n {ns}"))

            if cs.restart_count and cs.restart_count >= RESTART_THRESHOLD:
                sev = "CRITICAL" if cs.restart_count >= RESTART_THRESHOLD * 4 else "WARNING"
                issues.append(_issue(sev, "HighRestartCount", f"{ns}/{name}",
                    f"Container '{cn}' restarted {cs.restart_count}× — check logs for root cause",
                    when=created,
                    action=f"kubectl logs {name} -n {ns} -c {cn} --previous"))

    return issues


def check_events(core: client.CoreV1Api) -> List[Dict]:
    issues  = []
    cutoff  = _now() - timedelta(hours=EVENTS_LOOKBACK_H)
    seen    = set()

    try:
        events = core.list_event_for_all_namespaces(field_selector="type=Warning", limit=300)
    except ApiException:
        return []

    sorted_events = sorted(
        [e for e in events.items if e.last_timestamp],
        key=lambda e: e.last_timestamp,
        reverse=True,
    )
    del events

    for ev in sorted_events:
        ts = ev.last_timestamp
        if ts and ts.replace(tzinfo=timezone.utc) < cutoff:
            break

        ns     = ev.metadata.namespace or ev.involved_object.namespace or "?"
        obj    = ev.involved_object.name or "?"
        kind   = (ev.involved_object.kind or "").lower()
        reason = ev.reason or "Unknown"
        msg    = (ev.message or "")[:180]
        count  = ev.count or 1

        key = (ns, obj, reason)
        if key in seen:
            continue
        seen.add(key)

        resource_str = (f"{ns}/{obj}" if kind in
                        ("pod","deployment","replicaset","node","persistentvolumeclaim")
                        else f"{ns}/{kind}/{obj}")

        if reason in ("Evicting","Evicted","OOMKilling","SystemOOM","FreeDiskSpaceFailed",
                      "NodeNotReady","NodeHasDiskPressure","NodeHasInsufficientMemory"):
            sev = "CRITICAL"
        elif reason in ("BackOff","Failed","FailedCreate","FailedMount","FailedScheduling",
                        "FailedKillPod","NetworkNotReady","Unhealthy","ProbeWarning",
                        "ImageGCFailed","EvictionThresholdMet"):
            sev = "WARNING"
        else:
            sev = "INFO"

        count_str = f" (×{count})" if count > 1 else ""
        issues.append(_issue(sev, f"Event:{reason}", resource_str,
            f"{msg}{count_str}", when=ts))

    return issues


def check_pvcs(core: client.CoreV1Api) -> List[Dict]:
    issues = []
    old_pending = _now() - timedelta(minutes=15)

    for pvc in core.list_persistent_volume_claim_for_all_namespaces(limit=200).items:
        ns, name = pvc.metadata.namespace, pvc.metadata.name
        phase    = pvc.status.phase or ""
        created  = pvc.metadata.creation_timestamp

        if phase == "Lost":
            issues.append(_issue("CRITICAL", "PVCLost", f"{ns}/{name}",
                "PVC is LOST — underlying volume is gone. Pods depending on it will fail.",
                action=f"kubectl describe pvc {name} -n {ns}"))
        elif phase == "Pending":
            if created and created.replace(tzinfo=timezone.utc) < old_pending:
                sc = pvc.spec.storage_class_name or "default"
                issues.append(_issue("WARNING", "PVCPending", f"{ns}/{name}",
                    f"PVC stuck Pending for {_age(created)} (storageClass: {sc})",
                    when=created,
                    action=f"kubectl describe pvc {name} -n {ns}"))

    return issues


def check_daemonsets(apps: client.AppsV1Api) -> List[Dict]:
    issues = []
    for ds in apps.list_daemon_set_for_all_namespaces(limit=100).items:
        ns, name = ds.metadata.namespace, ds.metadata.name
        desired  = ds.status.desired_number_scheduled or 0
        ready    = ds.status.number_ready or 0
        if desired > 0 and ready < desired:
            issues.append(_issue("WARNING", "DaemonSetNotReady", f"{ns}/{name}",
                f"DaemonSet has {ready}/{desired} pods ready",
                action=f"kubectl rollout status ds/{name} -n {ns}"))
    return issues


def check_statefulsets(apps: client.AppsV1Api) -> List[Dict]:
    issues = []
    for sts in apps.list_stateful_set_for_all_namespaces(limit=100).items:
        ns, name = sts.metadata.namespace, sts.metadata.name
        desired  = sts.spec.replicas or 1
        ready    = sts.status.ready_replicas or 0
        if ready < desired:
            issues.append(_issue("WARNING", "StatefulSetNotReady", f"{ns}/{name}",
                f"StatefulSet has {ready}/{desired} pods ready",
                action=f"kubectl rollout status sts/{name} -n {ns}"))
    return issues


def check_jobs(batch: client.BatchV1Api) -> List[Dict]:
    issues = []
    for job in batch.list_job_for_all_namespaces(limit=200).items:
        ns, name  = job.metadata.namespace, job.metadata.name
        failed    = job.status.failed or 0
        succeeded = job.status.succeeded or 0
        created   = job.metadata.creation_timestamp
        if succeeded > 0 and failed == 0:
            continue
        if failed > 0:
            issues.append(_issue("WARNING", "JobFailed", f"{ns}/{name}",
                f"Job has {failed} failed attempt(s)",
                when=created,
                action=f"kubectl logs -l job-name={name} -n {ns} --tail=50"))
    return issues


def check_services(core: client.CoreV1Api) -> List[Dict]:
    issues = []
    ep_map: Dict[str, int] = {}
    for ep in core.list_endpoints_for_all_namespaces(limit=300).items:
        ns, name = ep.metadata.namespace, ep.metadata.name
        ready = 0
        for subset in (ep.subsets or []):
            ready += len(subset.addresses or [])
        ep_map[f"{ns}/{name}"] = ready

    for svc in core.list_service_for_all_namespaces(limit=300).items:
        ns, name = svc.metadata.namespace, svc.metadata.name
        if svc.spec.cluster_ip in ("None", "") or svc.spec.type == "ExternalName":
            continue
        if ns in SKIP_NS:
            continue
        if ns == "default" and name == "kubernetes":
            continue
        key   = f"{ns}/{name}"
        ready = ep_map.get(key, -1)
        if ready == 0 and svc.spec.selector:
            issues.append(_issue("WARNING", "ServiceNoEndpoints", key,
                "Service has a selector but 0 ready endpoints — selector may not match any pod",
                action=f"kubectl get endpoints {name} -n {ns}"))
    return issues


def check_replicasets(apps: client.AppsV1Api) -> List[Dict]:
    issues = []
    cutoff = _now() - timedelta(days=OLD_RS_DAYS)
    old_by_ns: Dict[str, List[str]] = {}

    for rs in apps.list_replica_set_for_all_namespaces(limit=500).items:
        desired = rs.spec.replicas or 0
        ready   = rs.status.ready_replicas or 0
        created = rs.metadata.creation_timestamp
        if desired == 0 and ready == 0 and created:
            if created.replace(tzinfo=timezone.utc) < cutoff:
                ns = rs.metadata.namespace
                old_by_ns.setdefault(ns, []).append(
                    f"{rs.metadata.name}({_age(created)})"
                )

    for ns, names in old_by_ns.items():
        s = ", ".join(names[:4])
        e = f" +{len(names)-4} more" if len(names) > 4 else ""
        issues.append(_issue("WARNING", "OldReplicaSets", f"namespace/{ns}",
            f"{len(names)} old 0/0/0 RSes holding image layers on disk: {s}{e}",
            action=f"kubectl get rs -n {ns} | awk 'NR>1&&$2==0&&$3==0{{print $1}}' | xargs kubectl delete rs -n {ns}"))
    return issues


def check_deployments(apps: client.AppsV1Api) -> List[Dict]:
    issues = []
    for dep in apps.list_deployment_for_all_namespaces(limit=300).items:
        ns, name = dep.metadata.namespace, dep.metadata.name
        if ns in SKIP_NS:
            continue

        rhl = dep.spec.revision_history_limit
        if rhl is not None and rhl > 3:
            issues.append(_issue("INFO", "HighRevisionHistory", f"{ns}/{name}",
                f"revisionHistoryLimit={rhl} keeps {rhl} old RSes pinning images on disk",
                action=(f"kubectl patch deploy {name} -n {ns} --type=json "
                        f"-p='[{{\"op\":\"replace\",\"path\":\"/spec/revisionHistoryLimit\",\"value\":2}}]'")))

        for c in dep.spec.template.spec.containers:
            cn  = c.name
            res  = c.resources or client.V1ResourceRequirements()
            lims = res.limits   or {}
            reqs = res.requests or {}

            if c.image_pull_policy == "Always":
                issues.append(_issue("WARNING", "ImagePullPolicyAlways", f"{ns}/{name}",
                    f"Container '{cn}' — imagePullPolicy:Always accumulates image layers on node disk",
                    action=f"Set imagePullPolicy: IfNotPresent in deployment {name}"))

            if "ephemeral-storage" not in lims:
                issues.append(_issue("WARNING", "NoEphemeralStorageLimit", f"{ns}/{name}",
                    f"Container '{cn}' — no ephemeral-storage limit, uncontrolled disk use causes node evictions",
                    action=f"Add: resources.limits.ephemeral-storage: 1Gi to container '{cn}'"))

            if not reqs.get("cpu") and not reqs.get("memory"):
                issues.append(_issue("WARNING", "NoPodRequests", f"{ns}/{name}",
                    f"Container '{cn}' — no CPU/memory requests (BestEffort QoS — first to be evicted)",
                    action=f"Add resource requests to deployment {name}"))

    return issues


def check_overcommit(node_items: list, pod_items: list) -> List[Dict]:
    issues = []
    alloc: Dict[str, Dict] = {}
    for node in node_items:
        a = node.status.allocatable or {}
        alloc[node.metadata.name] = {
            "cpu": _cpu(a.get("cpu",    "0")),
            "mem": _mem(a.get("memory", "0")),
        }

    req = {n: {"cpu": 0, "mem": 0} for n in alloc}
    lim = {n: {"cpu": 0, "mem": 0} for n in alloc}

    for pod in pod_items:
        n = pod.spec.node_name
        if not n or n not in alloc: continue
        if pod.status.phase not in ("Running", "Pending"): continue
        for c in pod.spec.containers:
            r = (c.resources.requests or {}) if c.resources else {}
            l = (c.resources.limits   or {}) if c.resources else {}
            req[n]["cpu"] += _cpu(r.get("cpu",    "0"))
            req[n]["mem"] += _mem(r.get("memory", "0"))
            lim[n]["cpu"] += _cpu(l.get("cpu",    "0"))
            lim[n]["mem"] += _mem(l.get("memory", "0"))

    for n, a in alloc.items():
        if not a["mem"]: continue
        mp = lim[n]["mem"] / a["mem"] * 100
        cp = (lim[n]["cpu"] / a["cpu"] * 100) if a["cpu"] else 0
        if mp > OVERCOMMIT_WARN_PCT:
            issues.append(_issue("WARNING", "MemLimitOvercommit", f"node/{n}",
                f"Memory limits at {mp:.0f}% of allocatable "
                f"({lim[n]['mem']}Mi limits vs {a['mem']}Mi available) — OOM kills likely under load"))
        if cp > OVERCOMMIT_WARN_PCT:
            issues.append(_issue("WARNING", "CPULimitOvercommit", f"node/{n}",
                f"CPU limits at {cp:.0f}% of allocatable "
                f"({lim[n]['cpu']}m limits vs {a['cpu']}m available) — throttling under load"))

    return issues


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ORCHESTRATOR                                                    ║
# ╚══════════════════════════════════════════════════════════════════╝

_SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

def run_all_checks() -> Tuple[Dict[str, Any], float]:
    """Returns (report_dict, duration_seconds)."""
    t0 = time.time()
    core, apps, batch = _clients()
    all_issues: List[Dict] = []

    try:
        node_items = core.list_node(limit=100).items
    except Exception as e:
        node_items = []
        all_issues.append(_issue("WARNING", "AgentError", "sre-agent", f"list_node failed: {e}"))

    try:
        pod_items = core.list_pod_for_all_namespaces(limit=500).items
    except Exception as e:
        pod_items = []
        all_issues.append(_issue("WARNING", "AgentError", "sre-agent", f"list_pods failed: {e}"))

    nodes_overview = []
    try:
        nodes_overview = node_overview(node_items)
    except Exception as e:
        all_issues.append(_issue("WARNING", "AgentError", "sre-agent", f"node_overview failed: {e}"))

    checks = [
        ("Nodes",        check_nodes,        (node_items,)),
        ("Pods",         check_pods,         (pod_items,)),
        ("Events",       check_events,       (core,)),
        ("PVCs",         check_pvcs,         (core,)),
        ("DaemonSets",   check_daemonsets,   (apps,)),
        ("StatefulSets", check_statefulsets, (apps,)),
        ("Jobs",         check_jobs,         (batch,)),
        ("Services",     check_services,     (core,)),
        ("ReplicaSets",  check_replicasets,  (apps,)),
        ("Deployments",  check_deployments,  (apps,)),
        ("Overcommit",   check_overcommit,   (node_items, pod_items)),
    ]

    for label, fn, args in checks:
        try:
            all_issues.extend(fn(*args))
        except ApiException as e:
            all_issues.append(_issue("WARNING", "AgentAPIError", "sre-agent",
                f"K8s API error in '{label}': {e.status} {e.reason}"))
        except Exception as e:
            all_issues.append(_issue("WARNING", "AgentError", "sre-agent",
                f"Check '{label}' failed: {e}"))

    del node_items
    del pod_items
    gc.collect()

    all_issues.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "INFO"), 3))

    summary = {
        "critical": sum(1 for i in all_issues if i["severity"] == "CRITICAL"),
        "warning":  sum(1 for i in all_issues if i["severity"] == "WARNING"),
        "info":     sum(1 for i in all_issues if i["severity"] == "INFO"),
    }

    report = {
        "cluster":        CLUSTER_NAME,
        "checked_at":     _now().isoformat(),
        "summary":        summary,
        "issues":         all_issues,
        "nodes_overview": nodes_overview,
        "healthy":        summary["critical"] == 0,
    }
    duration = time.time() - t0
    return report, duration


# ╔══════════════════════════════════════════════════════════════════╗
# ║  CLI PRINTER                                                     ║
# ╚══════════════════════════════════════════════════════════════════╝

def _print_rec(check_name: str, indent: str = "  "):
    """Print structured recommendation block for a check type, if available."""
    rec = _REC.get(check_name)
    if not rec:
        # Strip Event: prefix
        if check_name.startswith("Event:"):
            return
        return
    print(f"{indent}{DM}{'─'*68}{RS}")
    print(f"{indent}{B}🔍 Root Cause:{RS} {DM}{rec['root_cause'][:200]}{RS}")
    print(f"{indent}{Y}⚡ Immediate: {RS} {DM}{rec['immediate'][:200]}{RS}")
    print(f"{indent}{G}🛡  Prevent:  {RS} {DM}{rec['prevent'][:200]}{RS}")


def print_report(report: Dict[str, Any]):
    now_str  = report["checked_at"][:19].replace("T", " ")
    summary  = report["summary"]
    issues   = report["issues"]
    nodes    = report["nodes_overview"]

    crit_c, warn_c, info_c = summary["critical"], summary["warning"], summary["info"]

    print()
    print(_line("━"))
    print(f"{BD}{W}  🛡  SRE AGENT  │  {CLUSTER_NAME}  │  {now_str} UTC{RS}")
    print(_line("━"))

    crit_s = f"{R}{BD}{crit_c} Critical{RS}" if crit_c else f"{DM}{crit_c} Critical{RS}"
    warn_s = f"{Y}{BD}{warn_c} Warning{RS}"  if warn_c else f"{DM}{warn_c} Warning{RS}"
    info_s = f"{B}{info_c} Info{RS}"         if info_c else f"{DM}{info_c} Info{RS}"
    health = f"{G}{BD}✅ HEALTHY{RS}" if report["healthy"] else f"{R}{BD}⚠ ISSUES FOUND{RS}"
    print(f"\n  {health}   {crit_s}   {warn_s}   {info_s}\n")

    # ── Node Overview ──────────────────────────────────────────────────────────
    print(f"{BD}{DM}{'─'*W72}{RS}")
    print(f" {BD}NODES ({len(nodes)}){RS}")
    print(f"{BD}{DM}{'─'*W72}{RS}")
    for nd in nodes:
        name   = nd["name"].ljust(15)
        status = f"{G}Ready{RS}  " if nd["ready"] else f"{R}NOT READY{RS}"
        cpu    = f"cpu:{nd['cpu_m']}m"
        mem    = f"mem:{nd['mem_mi']}Mi"
        flags  = ("  " + "  ".join(nd["flags"])) if nd["flags"] else ""
        print(f"  {name} {status} │ {DM}{cpu:12}{RS} │ {DM}{mem:16}{RS} │ {DM}age:{nd['age']}{RS}{flags}")

    # ── Issues ─────────────────────────────────────────────────────────────────
    def _print_section(sev: str, label: str, color: str):
        filtered = [i for i in issues if i["severity"] == sev]
        if not filtered:
            return
        print(f"\n{BD}{color}{'─'*W72}")
        print(f" {label} ({len(filtered)}){RS}")
        print(f"{BD}{color}{'─'*W72}{RS}")
        for iss in filtered:
            if "ts" in iss and "age" in iss:
                time_str = f"{DM}[{iss['ts']}]  ({iss['age']} ago){RS}"
            elif "ts" in iss:
                time_str = f"{DM}[{iss['ts']}]{RS}"
            elif "age" in iss:
                time_str = f"{DM}(age: {iss['age']}){RS}"
            else:
                time_str = ""

            check_col = f"{BD}{color}{iss['check']:<28}{RS}"
            res_col   = f"{C}{iss['resource']}{RS}"
            print(f"  {check_col} {res_col}")
            if time_str:
                print(f"  {'':28} {time_str}")
            print(f"  {DM}{'':28}{RS} {iss['message']}")
            if "action" in iss:
                print(f"  {DM}{'':28} → {iss['action']}{RS}")
            # Print structured recommendation
            _print_rec(iss["check"])
            print()

    _print_section("CRITICAL", "🔴  CRITICAL", R)
    _print_section("WARNING",  "🟡  WARNING",  Y)
    _print_section("INFO",     "ℹ   INFO",      B)

    if not issues:
        print(f"\n  {G}{BD}All checks passed — cluster looks healthy!{RS}\n")

    actions = [i["action"] for i in issues if "action" in i and i["severity"] == "CRITICAL"]
    if actions:
        print(f"{BD}{DM}{'─'*W72}{RS}")
        print(f" {BD}QUICK ACTIONS (Critical){RS}")
        print(f"{BD}{DM}{'─'*W72}{RS}")
        for act in actions[:8]:
            print(f"  {Y}${RS}  {act}")
        print()

    print(_line("━"))
    print(f"  {DM}Next check in {CHECK_INTERVAL}s  │  :8080/metrics  :8080/health{RS}")
    print(_line("━"))
    print()


# ╔══════════════════════════════════════════════════════════════════╗
# ║  SLACK                                                           ║
# ╚══════════════════════════════════════════════════════════════════╝

_SE = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}


def send_slack(report: Dict[str, Any]):
    if not SLACK_WEBHOOK_URL:
        return
    issues  = report["issues"]
    summary = report["summary"]
    if not issues:
        return

    icon = "🔴" if summary["critical"] else "🟡"
    ts   = report["checked_at"][:19].replace("T", " ")

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": f"{icon} SRE Alert — {CLUSTER_NAME}"}},
        {"type": "section",
         "fields": [
             {"type": "mrkdwn", "text": f"*🔴 Critical:* {summary['critical']}"},
             {"type": "mrkdwn", "text": f"*🟡 Warning:* {summary['warning']}"},
             {"type": "mrkdwn", "text": f"*ℹ️ Info:* {summary['info']}"},
             {"type": "mrkdwn", "text": f"*🕒 At:* {ts} UTC"},
         ]},
        {"type": "divider"},
    ]

    for i, iss in enumerate(issues):
        if i >= 15:
            blocks.append({"type": "section",
                           "text": {"type": "mrkdwn",
                                    "text": f"_…and {len(issues)-15} more issues. Check /metrics or run kubectl._"}})
            break

        em = _SE.get(iss["severity"], "•")
        if "ts" in iss and "age" in iss:
            time_note = f"  `{iss['ts']}`  _({iss['age']} ago)_"
        elif "ts" in iss:
            time_note = f"  `{iss['ts']}`"
        elif "age" in iss:
            time_note = f"  _({iss['age']} ago)_"
        else:
            time_note = ""

        act = f"\n  → `{iss['action']}`" if "action" in iss and iss["severity"] == "CRITICAL" else ""

        # Add brief recommendation for CRITICAL issues
        rec_text = ""
        if iss["severity"] == "CRITICAL":
            rec = _REC.get(iss["check"])
            if rec:
                rec_text = f"\n  💡 _{rec['immediate'][:180]}_"

        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": (f"{em} *{iss['check']}* — `{iss['resource']}`{time_note}\n"
                                         f"{iss['message']}{act}{rec_text}")}})

    try:
        r = requests.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=10)
        if r.status_code != 200:
            print(f"[sre-agent] Slack error: {r.status_code} {r.text[:100]}", file=sys.stderr)
    except Exception as e:
        print(f"[sre-agent] Slack failed: {e}", file=sys.stderr)


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ENTRY POINT                                                     ║
# ╚══════════════════════════════════════════════════════════════════╝

def run_once():
    report, duration = run_all_checks()
    with _last_report_lock:
        _last_report.update(report)
    update_metrics(report, duration)
    print_report(report)
    send_slack(report)
    return report


def run_loop():
    ts_start = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts_start}] SRE Agent v3 started — cluster: {CLUSTER_NAME}  interval: {CHECK_INTERVAL}s")

    while True:
        try:
            report, duration = run_all_checks()

            with _last_report_lock:
                _last_report.update(report)
            update_metrics(report, duration)

            s      = report["summary"]
            ts_now = report["checked_at"][:19].replace("T", " ")
            n_nodes = len(report["nodes_overview"])

            if s["critical"] > 0 or s["warning"] > 0:
                print_report(report)
                send_slack(report)
            else:
                info_s = f"  {s['info']} info" if s["info"] else ""
                print(
                    f"[{ts_now} UTC] {G}✅ All clear{RS}"
                    f"  nodes:{n_nodes}{info_s}"
                    f"  dur:{duration:.1f}s"
                    f"  next:{CHECK_INTERVAL}s"
                )

        except Exception as e:
            ts_err = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts_err}] [sre-agent] Cycle error: {e}", file=sys.stderr)

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    _setup_rec_metrics()   # populate sre_check_rec_info once at startup
    start_metrics_server()
    if "--once" in sys.argv:
        run_once()
    else:
        run_loop()

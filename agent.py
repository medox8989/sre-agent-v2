#!/usr/bin/env python3
"""
SRE Agent v4 — Kubernetes Cluster Health Monitor
Self-contained Web UI + Slack alerting + CLI output.

Run modes:
  python agent.py            # continuous loop (default)
  python agent.py --once     # run once, print, exit
  python agent.py --events   # event timeline CLI report
  python agent.py --incidents# scaling incident analysis
  python agent.py --odoo     # Odoo config health report

Web UI (port 8080):
  /                  — Self-contained cluster health dashboard
  /health            — JSON health check (used by K8s liveness probe)
  /api/status        — Latest check result as JSON
  /api/history       — Historical snapshots (?hours=N, default 1)
  /api/node-events   — Node scaling/status events (?hours=N, default 6)

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
  Security     — Privileged containers, RBAC wildcards, host mounts, hardcoded secrets
  OdooConfig   — Ladder-of-Limits compliance (hard/soft/workers/HPA)
"""

import gc
import re
import sys
import os
import time
import json
import logging
import threading
import http.server
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException

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
SCALING_RECENT_MINS  = int(os.getenv("SCALING_RECENT_MINUTES", "15"))
SCALING_HISTORY_H    = int(os.getenv("SCALING_HISTORY_HOURS",  "6"))
EVENTS_ACTIVE_MINS   = int(os.getenv("EVENTS_ACTIVE_MINUTES",  "5"))
EVENTS_RECENT_MINS   = int(os.getenv("EVENTS_RECENT_MINUTES",  "30"))

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
    # ── Security checks (Kubernetes Goat scenarios) ──────────────────────────
    "PrivilegedContainer": {
        "root_cause": "Container runs with securityContext.privileged:true — it gets all Linux capabilities "
                      "and can see and modify host devices, network stack, and kernel modules. "
                      "Any RCE inside this container is a full host escape. (Kubernetes Goat sc-4)",
        "immediate":  "kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext}'. "
                      "Remove privileged:true. Almost no application needs it — only special node agents do.",
        "prevent":    "Use Pod Security Admission (restricted profile). "
                      "Enforce via Kyverno/OPA: deny containers with privileged:true at admission time.",
    },
    "DockerSocketMount": {
        "root_cause": "Container mounts /var/run/docker.sock as a hostPath volume. "
                      "This gives full Docker daemon access — anyone inside the container can create a "
                      "privileged container that mounts the host filesystem. Full host escape. (Goat sc-2)",
        "immediate":  "Remove the hostPath volume for /var/run/docker.sock immediately. "
                      "Use a dedicated build tool (Kaniko, Buildah) inside the cluster instead.",
        "prevent":    "Never mount the Docker socket in production pods. "
                      "Use remote build services or in-cluster Kaniko for CI/CD image builds.",
    },
    "DangerousHostPath": {
        "root_cause": "Container mounts a sensitive host filesystem path (/etc, /proc, /sys, /root, /boot) "
                      "via hostPath volume. This enables reading host credentials, modifying sysctl, "
                      "or writing to init scripts — effectively a host root access vector. (Goat sc-4)",
        "immediate":  "kubectl describe pod <pod> -n <ns> to see volume mounts. "
                      "Remove the hostPath volume and replace with an emptyDir or ConfigMap if possible.",
        "prevent":    "Use Pod Security Admission to deny hostPath volumes. "
                      "Audit all existing hostPath mounts: kubectl get pods -A -o json | "
                      "jq '.items[].spec.volumes[]? | select(.hostPath)'",
    },
    "HostNetworkPod": {
        "root_cause": "Pod has hostNetwork:true — it shares the node's network namespace, can bind to "
                      "any port on the node's real IP, and can sniff all pod-to-pod traffic on the node. "
                      "Bypasses NetworkPolicy for inter-pod communication. (Goat sc-11)",
        "immediate":  "Verify this is intentional (e.g., node-level monitoring agents like Falco). "
                      "For application pods: remove hostNetwork:true immediately.",
        "prevent":    "Application pods should never need hostNetwork. "
                      "Restrict to specific system namespaces via Pod Security Admission.",
    },
    "HostPIDPod": {
        "root_cause": "Pod has hostPID:true — it can see all processes running on the host, including "
                      "processes from other containers. An attacker can use /proc/<pid>/mem to read "
                      "memory of any host process, extract secrets, or inject code. (Goat sc-4)",
        "immediate":  "Remove hostPID:true unless this is a dedicated debugging or monitoring tool.",
        "prevent":    "Enforce via Pod Security Admission (hostPID is forbidden in restricted profile). "
                      "Use ephemeral containers with kubectl debug for ad-hoc process inspection.",
    },
    "HostIPCPod": {
        "root_cause": "Pod has hostIPC:true — it shares the host's IPC namespace. "
                      "An attacker inside the pod can attach to shared memory segments of other processes "
                      "on the host, potentially extracting data from databases or application caches.",
        "immediate":  "Remove hostIPC:true. Very few legitimate workloads require this.",
        "prevent":    "Enforce via Pod Security Admission. "
                      "Audit: kubectl get pods -A -o json | jq '.items[] | select(.spec.hostIPC==true)'",
    },
    "RBACWildcardRole": {
        "root_cause": "A Role or ClusterRole uses wildcard verbs (*) or wildcard resources (*), "
                      "granting permissions that are far broader than needed. "
                      "A compromised pod bound to this role can read secrets, exec into pods, "
                      "or modify cluster state. (Kubernetes Goat sc-16)",
        "immediate":  "kubectl describe clusterrole <name> to see the exact rules. "
                      "Replace wildcards with the specific verbs/resources actually needed.",
        "prevent":    "Follow least-privilege RBAC: grant only get/list on specific resources. "
                      "Use 'kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>' to audit.",
    },
    "RBACClusterAdminBinding": {
        "root_cause": "A ServiceAccount in a non-system namespace is bound to the cluster-admin ClusterRole. "
                      "This is the highest privilege in Kubernetes — it bypasses all authorization checks. "
                      "A compromised pod with this SA can delete namespaces, read all secrets, "
                      "and modify RBAC itself. (Kubernetes Goat sc-16)",
        "immediate":  "kubectl describe clusterrolebinding <name> to see what binds to cluster-admin. "
                      "Replace with a scoped ClusterRole granting only what is actually needed.",
        "prevent":    "Never bind cluster-admin to application service accounts. "
                      "Regularly audit: kubectl get clusterrolebindings -o json | "
                      "jq '.items[] | select(.roleRef.name==\"cluster-admin\")'",
    },
    "HardcodedSecret": {
        "root_cause": "A container has an environment variable whose name indicates a secret "
                      "(PASSWORD, TOKEN, API_KEY, SECRET, etc.) but whose value is a plain literal "
                      "string — not a secretKeyRef. The value is visible in 'kubectl describe pod', "
                      "kubectl get pod -o yaml, and any audit log. (Kubernetes Goat sc-1)",
        "immediate":  "kubectl create secret generic <name> --from-literal=<KEY>=<value> -n <ns>. "
                      "Update the deployment to use secretKeyRef instead of the literal value. "
                      "Consider the secret compromised and rotate it.",
        "prevent":    "Use Kubernetes Secrets + secretKeyRef for all credentials. "
                      "Use External Secrets Operator or OCI Vault to sync secrets into the cluster. "
                      "Scan deployments with: kubectl get deploy -A -o json | jq to detect plaintext creds.",
    },
    "NoNetworkPolicy": {
        "root_cause": "The namespace has running pods but no NetworkPolicy defined. "
                      "In a flat network (default Kubernetes), every pod can reach every other pod "
                      "across all namespaces — a compromised Odoo pod can directly connect to your "
                      "PostgreSQL DB, Redis, or internal services in other namespaces. (Goat sc-20)",
        "immediate":  "Apply a default-deny-all ingress policy first, then whitelist only required paths. "
                      "kubectl apply -f default-deny-ingress.yaml -n <ns>",
        "prevent":    "Every production namespace should have at minimum a default-deny ingress policy. "
                      "Use Calico or Cilium for namespace-level network segmentation.",
    },
    "NodePortExposed": {
        "root_cause": "Service type NodePort opens a port directly on every node's public IP address. "
                      "Any host that can reach the node (including the internet if nodes have public IPs) "
                      "can connect to the service — bypassing your Ingress and WAF. (Kubernetes Goat sc-8)",
        "immediate":  "Switch to type: ClusterIP and expose via an Ingress controller. "
                      "If NodePort is needed temporarily, restrict via OCI Security List / NSG rules.",
        "prevent":    "Use ClusterIP + Ingress as the standard pattern. "
                      "Reserve NodePort/LoadBalancer for specific infrastructure services only.",
    },
    "ContainerRunsAsRoot": {
        "root_cause": "Container has no runAsNonRoot:true or runAsUser set in securityContext. "
                      "It likely runs as UID 0 (root) inside the container. "
                      "Combined with any container escape, the attacker has root on the host node.",
        "immediate":  "Add securityContext: runAsNonRoot: true and runAsUser: 1000 (or app-specific UID). "
                      "Test the app starts correctly with a non-root UID.",
        "prevent":    "Build images with a non-root USER in the Dockerfile. "
                      "Enforce runAsNonRoot:true via Pod Security Admission or Kyverno policy.",
    },
    "AutomountSAToken": {
        "root_cause": "Pod uses the default ServiceAccount with automountServiceAccountToken:true (the K8s default). "
                      "A token granting Kubernetes API access is mounted at /var/run/secrets/kubernetes.io/serviceaccount. "
                      "If the app is compromised, the attacker can query the K8s API with this token. (Goat sc-11)",
        "immediate":  "If the pod doesn't need K8s API access, add automountServiceAccountToken: false "
                      "to the pod spec or ServiceAccount.",
        "prevent":    "Set automountServiceAccountToken: false on the default ServiceAccount in every namespace. "
                      "Create dedicated SAs with minimal permissions only for pods that actually need API access.",
    },
    "DangerousCapability": {
        "root_cause": "Container adds a Linux capability (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, NET_RAW, etc.) "
                      "that significantly expands what root processes inside the container can do. "
                      "SYS_ADMIN alone is nearly equivalent to full privilege.",
        "immediate":  "kubectl describe pod <pod> -n <ns> | grep -A5 Capabilities. "
                      "Remove the capability from securityContext.capabilities.add if not strictly needed.",
        "prevent":    "Default: drop ALL capabilities and add back only what is required. "
                      "securityContext.capabilities.drop: [ALL], then add: only the specific caps needed.",
    },
    # ── Scaling / HPA incident patterns ─────────────────────────────────────
    "HPAFlapping": {
        "root_cause": "HPA triggered a scale-up but scaled back down before the new pod became ready. "
                      "Typical causes: (1) large image pull time (4GB = 2+ min) keeps the pod 'unready', "
                      "causing HPA metrics to drop once the new pod is counted in the replica set; "
                      "(2) HPA downscale-stabilization window too short (default 5 min); "
                      "(3) CPU spike was transient — load was gone by the time the new node joined.",
        "immediate":  "Set HPA scaleDown.stabilizationWindowSeconds: 300 (or higher). "
                      "Set minReplicas ≥ 2 so scale-up starts from a warm base. "
                      "Reduce image size (multi-stage build, target <1 GB) to shorten pull time.",
        "prevent":    "Add HPA behavior block: scaleDown.stabilizationWindowSeconds: 600. "
                      "Pre-pull images on nodes using a DaemonSet or node start-up script. "
                      "Use image digests + IfNotPresent so nodes that already have the image start instantly.",
    },
    "CNINotReady": {
        "root_cause": "Cluster autoscaler added a new node, but the Flannel CNI DaemonSet pod "
                      "on that node had not finished writing /run/flannel/subnet.env before the workload "
                      "pod was scheduled. Flannel must contact the API server and allocate a subnet first — "
                      "this takes 30–90 seconds on a freshly booted OKE node.",
        "immediate":  "This self-heals: kubelet retries sandbox creation. If stuck, delete the pod: "
                      "kubectl delete pod <pod> -n <ns> to force a reschedule. "
                      "Check Flannel on node: kubectl get pod -n kube-system -l app=flannel -o wide",
        "prevent":    "Ensure Flannel DaemonSet has priorityClassName: system-node-critical. "
                      "Configure cluster-autoscaler with --balance-similar-node-groups. "
                      "Add a node startup taint that is removed only after Flannel is ready (init DaemonSet pattern).",
    },
    "HPAMetricLag": {
        "root_cause": "After a pod is evicted/rescheduled its IP changes. The metrics-server scrapes "
                      "kubelet for pod CPU/memory — it takes 1–2 scrape intervals (60s total) before "
                      "metrics return. During this gap the HPA sees 'no metrics' and cannot scale. "
                      "This is normal behaviour but can mask a real load spike.",
        "immediate":  "No action needed — this is transient. Verify: kubectl top pod -n <ns>. "
                      "If persistent (>5 min): kubectl get apiservice v1beta1.metrics.k8s.io -o yaml",
        "prevent":    "Keep minReplicas ≥ 2 so HPA always has at least one pod reporting metrics. "
                      "Set metrics-server --metric-resolution=15s to shorten the lag. "
                      "Use behavior.scaleUp.stabilizationWindowSeconds: 60 to prevent premature decisions.",
    },
    "NodeScaleDelay": {
        "root_cause": "OKE node provisioning takes 2–5 minutes: VM boot, kubelet start, node registration, "
                      "DaemonSet scheduling (Flannel, kube-proxy), CNI initialization. "
                      "Workload pods remain Pending for this entire window. "
                      "If the CPU spike that triggered scale-up was transient, load is gone before the node joins.",
        "immediate":  "Wait for the node to become Ready: kubectl get nodes -w. "
                      "Check autoscaler progress: kubectl logs -n kube-system -l app=cluster-autoscaler --tail=50",
        "prevent":    "Keep a small buffer of spare capacity with a low-priority placeholder Deployment. "
                      "Set HPA scaleUp triggers at lower CPU% (e.g. 60%) so scale-up starts earlier. "
                      "Use OKE virtual nodes (serverless) for near-instant capacity if available in your region.",
    },

    # ── Odoo Ladder-of-Limits checks ─────────────────────────────────────────
    # Reference:  hard = 80% of K8s limit   soft = 80% of K8s request
    #             HPA memory target = 80% of request   workers = 2 × CPU cores

    "OdooHardExceedsK8sLimit": {
        "root_cause": "limit_memory_hard > K8s memory limit. The Linux OOM killer evicts the pod "
                      "before Odoo can gracefully restart the worker. This causes hard pod crashes "
                      "instead of clean worker recycling and is the #1 cause of unexpected OOMKills.",
        "immediate":  "Lower limit_memory_hard to ≤ 80% of K8s limit "
                      "(formula: K8s_limit_GiB × 0.80 × 1,073,741,824 bytes). "
                      "Alternatively raise the K8s memory limit, then redeploy.",
        "prevent":    "Follow the Ladder of Limits: hard = 80% of K8s limit, soft = 80% of K8s request. "
                      "Encode these ratios in your Helm values so they stay in sync automatically.",
    },
    "OdooHardTooCloseToLimit": {
        "root_cause": "limit_memory_hard > 90% of K8s limit. Less than 10% headroom between the Odoo "
                      "worker kill threshold and the K8s OOM eviction wall. Any transient memory spike "
                      "(e.g. a large report) kills the pod instead of restarting the worker.",
        "immediate":  "Reduce limit_memory_hard to ≤ 85% of K8s limit to restore a safe buffer.",
        "prevent":    "Target hard = 80% of K8s limit. Keep at least 15–20% headroom "
                      "for the Odoo process overhead beyond the worker heap.",
    },
    "OdooHardRatioLow": {
        "root_cause": "limit_memory_hard < 70% of K8s limit. Workers are being killed and restarted "
                      "well below the guaranteed K8s memory allocation — wasting up to 30% of reserved "
                      "memory and causing excessive worker churn.",
        "immediate":  "Raise limit_memory_hard toward 80% of K8s limit "
                      "(formula: K8s_limit_GiB × 0.80 × 1,073,741,824 bytes).",
        "prevent":    "Revisit memory sizing holistically: K8s request = expected working set, "
                      "K8s limit = peak allowance, hard = 80% of limit.",
    },
    "OdooSoftExceedsHard": {
        "root_cause": "limit_memory_soft ≥ limit_memory_hard. The Ladder of Limits is inverted: "
                      "Odoo will never trigger a graceful worker restart (soft) because the hard kill "
                      "threshold is reached first. Every worker termination is abrupt.",
        "immediate":  "Correct the order: set soft < hard. "
                      "Recommended: soft = 80% of K8s request, hard = 80% of K8s limit.",
        "prevent":    "Validate both values together whenever either is changed. "
                      "Add a CI check: assert limit_memory_soft < limit_memory_hard.",
    },
    "OdooSoftExceedsRequest": {
        "root_cause": "limit_memory_soft > K8s memory request. Workers restart when memory exceeds "
                      "the guaranteed K8s allocation, but at that point the node scheduler may have "
                      "already over-committed the node, making the pod vulnerable to eviction during restart.",
        "immediate":  "Lower limit_memory_soft to ≤ K8s request (recommended: 80% of request).",
        "prevent":    "Set soft = 80% of K8s request. This ensures graceful restarts happen within "
                      "the guaranteed allocation window, before any node pressure builds.",
    },
    "OdooSoftRatioLow": {
        "root_cause": "limit_memory_soft < 60% of K8s request. Workers restart excessively — "
                      "for a 2.5 GiB request this means restarting at ~1.5 GiB, wasting 1 GiB of reserved memory "
                      "and causing high worker churn that degrades request throughput.",
        "immediate":  "Raise limit_memory_soft toward 80% of K8s request.",
        "prevent":    "Target soft = 80% of K8s request. Tune upward if workers still restart too frequently.",
    },
    "WorkersMissing": {
        "root_cause": "workers = 0 means Odoo is running in single-process (threaded) mode. "
                      "There are no separate worker processes — one slow or blocked request delays all others. "
                      "Memory limits and OOM kills are also less predictable in this mode.",
        "immediate":  "Set workers = 2 in odoo.conf (or = 1 for 0.5 CPU deployments). "
                      "Restart the pod to apply: kubectl rollout restart deployment/<name>",
        "prevent":    "Always set workers ≥ 1 for production. 2 workers per CPU core is the standard rule.",
    },
    "WorkerCountMismatch": {
        "root_cause": "The number of Odoo workers does not match the CPU request. "
                      "Too many workers → context-switch overhead, higher memory pressure, slower individual requests. "
                      "Too few workers → CPU cores idle, low concurrency, wasted node resources.",
        "immediate":  "Set workers = floor(cpu_request × 2). "
                      "For 0.5 CPU → workers=1, for 1 CPU → workers=2, for 2 CPU → workers=4.",
        "prevent":    "Keep workers = 2 × cpu_request as the standard ratio. "
                      "Change workers and cpu_request together in the same deployment update.",
    },
    "HpaNotFound": {
        "root_cause": "No HorizontalPodAutoscaler exists for this Odoo deployment. "
                      "A single pod handles all traffic — no scale-out on load spikes, "
                      "and any OOMKill leaves the service with zero replicas during restart.",
        "immediate":  "Create an HPA targeting memory=80% and cpu=75%: "
                      "kubectl apply -f hpa.yaml (see QUICK_REFERENCE for the full spec).",
        "prevent":    "Include HPA in your standard deployment template. "
                      "minReplicas=1, maxReplicas=5, memory=80%, cpu=75%, "
                      "scaleDown.stabilizationWindowSeconds=300.",
    },
    "HpaMemoryMisaligned": {
        "root_cause": "The HPA memory trigger point (averageUtilization% × K8s request) does not match "
                      "limit_memory_soft. The HPA should scale out exactly when memory approaches the soft limit — "
                      "triggering too early wastes pods, triggering too late means workers die before help arrives.",
        "immediate":  "Set HPA memory averageUtilization = round(limit_memory_soft / k8s_request × 100). "
                      "For soft=2.0GiB and request=2.5GiB: averageUtilization=80.",
        "prevent":    "Always derive HPA memory target from the soft/request ratio. "
                      "When you change request or soft, recalculate and update the HPA.",
    },
    "HpaMaxTooLow": {
        "root_cause": "HPA maxReplicas < 3. Very limited scaling headroom — a load spike that requires "
                      "more than 2 replicas will cause sustained degradation with no further scale-out.",
        "immediate":  "Raise maxReplicas to at least 3 (recommended: 5). "
                      "kubectl patch hpa <name> -n <ns> -p '{\"spec\":{\"maxReplicas\":5}}'",
        "prevent":    "Set maxReplicas based on node capacity. Default recommendation: 5. "
                      "Review and increase during traffic growth.",
    },
    "HpaCpuTargetHigh": {
        "root_cause": "HPA CPU averageUtilization target > 85%. Pods run near 100% CPU before "
                      "scale-out is triggered — during the 1–2 min provisioning window "
                      "request latency degrades significantly.",
        "immediate":  "Lower cpu averageUtilization to 75% for faster, earlier scale-out.",
        "prevent":    "Target 70–75% CPU utilization to give a comfortable buffer before saturation.",
    },
    "HpaScaleDownFast": {
        "root_cause": "HPA scaleDown stabilizationWindowSeconds < 120. Scale-down happens too quickly "
                      "after load drops, causing thrashing: new pods start → scale-up → scale-down → "
                      "load returns → scale-up again in a rapid cycle.",
        "immediate":  "Set scaleDown.stabilizationWindowSeconds ≥ 300 (5 minutes).",
        "prevent":    "Use 300s as the default. Only reduce for batch/queue workloads where "
                      "rapid scale-down is desired.",
    },
    "LimitRequestTooLow": {
        "root_cause": "limit_request < 4096. Odoo workers restart after fewer than 4096 HTTP requests — "
                      "very high worker churn rate, warm-up overhead on every restart, "
                      "and more frequent transient errors during recycling.",
        "immediate":  "Set limit_request = 8192 in odoo.conf (standard value for production).",
        "prevent":    "Use 8192 as default. Increase to 16384 if workers still restart too frequently "
                      "and memory growth is stable.",
    },
    "LimitTimeMissing": {
        "root_cause": "limit_time_cpu or limit_time_real is 0 (unlimited). A runaway request "
                      "(e.g. a slow report, infinite loop in custom code) can lock up a worker indefinitely, "
                      "gradually exhausting the worker pool.",
        "immediate":  "Set limit_time_cpu = 600 (10 min) and limit_time_real = 1200 (20 min).",
        "prevent":    "Always set both. Increase only for known long-running operations "
                      "(scheduled actions run in separate cron workers and are not affected).",
    },
    "LogfileEnabled": {
        "root_cause": "logfile is set to a file path instead of False. In Kubernetes, containers "
                      "should write logs to stdout/stderr so kubelet/fluentd can collect them. "
                      "Writing to a file inside the container: (1) fills ephemeral storage, "
                      "(2) requires log rotation config, (3) is invisible to kubectl logs.",
        "immediate":  "Set logfile = False in odoo.conf and restart the pod.",
        "prevent":    "Always use logfile = False for K8s deployments. "
                      "Ship logs via stdout → fluentd/Loki → Grafana.",
    },
    "OdooConfigNotFound": {
        "root_cause": "The SRE agent could not locate an odoo.conf ConfigMap for this Odoo deployment. "
                      "Ladder-of-Limits compliance cannot be verified without reading the configuration.",
        "immediate":  "Ensure a ConfigMap with odoo.conf data is mounted into the Odoo pod "
                      "(either via volume or envFrom), or that it is in the same namespace as the deployment.",
        "prevent":    "Standardize ConfigMap naming: use 'odoo-config' or include 'odoo' and 'conf' "
                      "in the name so the SRE agent can auto-discover it.",
    },
}


# ╔══════════════════════════════════════════════════════════════════╗
# ║  DATA STORE  — in-memory ring buffer of check snapshots          ║
# ╚══════════════════════════════════════════════════════════════════╝

class DataStore:
    """Stores cluster check data in two separate structures to minimise memory:

    - _latest   : single full report dict (the most recent cycle, ~50-200 KB)
    - _history  : lightweight deque of {ts, duration, summary} — no issue lists,
                  no nodes_overview.  Each entry ≈ 200 bytes.

    At CHECK_INTERVAL=300s this gives ≤ 288 history entries per 24 h.
    We also cap at MAX_SNAPS so a fast interval can't blow up memory.
    """
    MAX_AGE_HOURS = 24
    MAX_SNAPS     = 300    # hard cap regardless of interval

    def __init__(self):
        self._lock    = threading.Lock()
        self._latest: Optional[Dict] = None          # full snapshot: {ts, duration, report}
        self._history: deque         = deque()        # lightweight: {ts, duration, summary}

    def add(self, report: Dict, duration: float) -> None:
        ts     = _now().isoformat()
        cutoff = (_now() - timedelta(hours=self.MAX_AGE_HOURS)).isoformat()
        with self._lock:
            self._latest = {"ts": ts, "duration": round(duration, 2), "report": report}
            self._history.append({"ts": ts, "duration": round(duration, 2),
                                   "summary": report["summary"]})
            # Trim by age
            while self._history and self._history[0]["ts"] < cutoff:
                self._history.popleft()
            # Trim by count (safety cap)
            while len(self._history) > self.MAX_SNAPS:
                self._history.popleft()

    def latest(self) -> Optional[Dict]:
        """Return the most recent full snapshot dict or None."""
        with self._lock:
            return self._latest

    def history(self, hours: float = 1.0) -> List[Dict]:
        """Return lightweight history entries for the last N hours."""
        cutoff = (_now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            return [s for s in self._history if s["ts"] >= cutoff]


_data_store = DataStore()


# ╔══════════════════════════════════════════════════════════════════╗
# ║  NODE WATCHER  — detects node add / remove / NotReady events     ║
# ╚══════════════════════════════════════════════════════════════════╝

class NodeWatcher:
    """Polls the cluster every poll_interval seconds and logs node state changes.

    The K8s API client is created once on first use and reused for all
    subsequent polls to avoid repeated config loading overhead.
    """
    MAX_AGE_HOURS = 24
    MAX_EVENTS    = 500   # hard cap on stored events

    def __init__(self, poll_interval: int = 60):
        self._lock              = threading.Lock()
        self._events: deque     = deque()
        self._known: Dict[str, str] = {}   # name → "ready" | "notready"
        self._poll_interval     = poll_interval
        self._core              = None     # cached CoreV1Api client

    def start(self) -> None:
        t = threading.Thread(target=self._run, name="node-watcher", daemon=True)
        t.start()

    def _run(self) -> None:
        # First call: seed _known without emitting events (baseline)
        try:
            self._seed()
        except Exception as e:
            logging.debug(f"NodeWatcher seed: {e}")
        while True:
            time.sleep(self._poll_interval)
            try:
                self._poll()
            except Exception as e:
                logging.debug(f"NodeWatcher poll: {e}")
                self._core = None   # reset client on error so next poll re-creates it

    def _get_core(self) -> client.CoreV1Api:
        """Return a cached CoreV1Api client, creating it once on first use."""
        if self._core is None:
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            self._core = client.CoreV1Api()
        return self._core

    def _seed(self) -> None:
        core  = self._get_core()
        nodes = core.list_node(limit=100).items
        with self._lock:
            for n in nodes:
                conds = {c.type: c.status for c in (n.status.conditions or [])}
                self._known[n.metadata.name] = "ready" if conds.get("Ready") == "True" else "notready"

    def _poll(self) -> None:
        core   = self._get_core()
        items  = core.list_node(limit=100).items
        now_s  = _now().isoformat()
        cutoff = (_now() - timedelta(hours=self.MAX_AGE_HOURS)).isoformat()

        new_known: Dict[str, str] = {}
        for n in items:
            conds = {c.type: c.status for c in (n.status.conditions or [])}
            new_known[n.metadata.name] = "ready" if conds.get("Ready") == "True" else "notready"

        with self._lock:
            added   = set(new_known) - set(self._known)
            removed = set(self._known) - set(new_known)
            changed = {nm for nm in set(new_known) & set(self._known) if new_known[nm] != self._known[nm]}

            for nm in added:
                self._events.append({"ts": now_s, "node": nm, "type": "NodeAdded",    "detail": new_known[nm]})
            for nm in removed:
                self._events.append({"ts": now_s, "node": nm, "type": "NodeRemoved",  "detail": ""})
            for nm in changed:
                etype = "NodeNotReady" if new_known[nm] == "notready" else "NodeRecovered"
                self._events.append({"ts": now_s, "node": nm, "type": etype,           "detail": ""})

            self._known = new_known
            while self._events and self._events[0]["ts"] < cutoff:
                self._events.popleft()
            while len(self._events) > self.MAX_EVENTS:
                self._events.popleft()

    def get_events(self, hours: float = 6.0) -> List[Dict]:
        cutoff = (_now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            return [e for e in self._events if e["ts"] >= cutoff]


_node_watcher = NodeWatcher(poll_interval=60)


# ╔══════════════════════════════════════════════════════════════════╗
# ║  WEB UI  — self-contained dashboard served at /                  ║
# ╚══════════════════════════════════════════════════════════════════╝

_WEB_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SRE Agent</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;
      --red:#f85149;--yel:#e3b341;--blu:#58a6ff;--grn:#3fb950;--pur:#d2a8ff;--org:#ffa657;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--tx);font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',monospace;}
a{color:var(--blu);}
#rp{height:2px;background:var(--blu);position:fixed;top:0;left:0;transition:width 1s linear;z-index:100;}
#eb{background:#3d1111;border-bottom:1px solid var(--red);color:var(--red);padding:6px 20px;font-size:12px;display:none;}
header{background:var(--bg2);border-bottom:1px solid var(--bd);padding:10px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
header h1{font-size:15px;font-weight:700;}
#cluster-name{color:var(--blu);font-weight:600;}
#last-check{color:var(--mu);font-size:11px;margin-left:auto;}
.sdot{width:9px;height:9px;border-radius:50%;display:inline-block;}
.sdot-ok{background:var(--grn);box-shadow:0 0 5px var(--grn);}
.sdot-err{background:var(--red);box-shadow:0 0 5px var(--red);}
.cards{display:flex;gap:10px;padding:14px 20px;flex-wrap:wrap;}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:7px;padding:12px 16px;min-width:100px;}
.card .lbl{color:var(--mu);font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px;}
.card .val{font-size:26px;font-weight:700;line-height:1.1;}
.c-crit{border-left:3px solid var(--red);}  .c-crit .val{color:var(--red);}
.c-warn{border-left:3px solid var(--yel);}  .c-warn .val{color:var(--yel);}
.c-info{border-left:3px solid var(--blu);}  .c-info .val{color:var(--blu);}
.c-node{border-left:3px solid var(--grn);}  .c-node .val{color:var(--grn);}
.c-dur {border-left:3px solid var(--pur);}  .c-dur  .val{color:var(--pur);font-size:18px;padding-top:3px;}
.ctrl{padding:0 20px 10px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
.ctrl label{color:var(--mu);font-size:10px;text-transform:uppercase;letter-spacing:.06em;}
.btn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx);padding:3px 9px;
     border-radius:4px;cursor:pointer;font-size:12px;transition:background .12s;}
.btn:hover{background:#2d333b;}
.btn.on{background:#1f6feb;border-color:#388bfd;color:#fff;}
.sev-C{color:var(--red);}   .sev-C.on{background:rgba(248,81,73,.15);border-color:var(--red);}
.sev-W{color:var(--yel);}   .sev-W.on{background:rgba(227,179,65,.15);border-color:var(--yel);}
.sev-I{color:var(--blu);}   .sev-I.on{background:rgba(88,166,255,.15);border-color:var(--blu);}
section{padding:0 20px 18px;}
h2{font-size:11px;font-weight:600;color:var(--mu);text-transform:uppercase;letter-spacing:.08em;
   padding:10px 0 5px;border-top:1px solid var(--bd);display:flex;align-items:center;gap:6px;}
h2 .cnt{font-weight:400;color:var(--mu);}
.ns-group{margin-bottom:14px;}
.ns-hdr{font-size:10px;font-weight:700;color:var(--org);text-transform:uppercase;letter-spacing:.07em;
        padding:4px 0 3px;border-bottom:1px solid var(--bd);margin-bottom:4px;}
table{width:100%;border-collapse:collapse;}
th{text-align:left;padding:6px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;
   color:var(--mu);border-bottom:1px solid var(--bd);background:var(--bg2);position:sticky;top:0;}
td{padding:5px 10px;border-bottom:1px solid #1c2128;vertical-align:top;font-size:12px;word-break:break-word;}
tr:hover td{background:var(--bg3);}
.sv-CRITICAL{color:var(--red);font-weight:600;}
.sv-WARNING{color:var(--yel);font-weight:600;}
.sv-INFO{color:var(--blu);}
.mono{font-family:monospace;font-size:11px;}
.mu{color:var(--mu);}
.rdy{color:var(--grn);}
.nrdy{color:var(--red);font-weight:600;}
.ev-A{color:var(--grn);}
.ev-R{color:var(--red);}
.ev-N{color:var(--yel);}
.ev-V{color:var(--grn);}
.empty{color:var(--mu);font-style:italic;padding:10px 0;font-size:12px;}
.ts-cell{white-space:nowrap;color:var(--mu);font-size:11px;}
.cur-state{color:var(--mu);font-size:10px;font-style:italic;}
.rec{margin-top:4px;padding:4px 8px;background:rgba(88,166,255,.07);border-left:2px solid var(--blu);
     color:var(--mu);font-size:11px;border-radius:0 3px 3px 0;}
.rec-lbl{color:var(--blu);font-weight:600;font-size:10px;text-transform:uppercase;margin-right:4px;}
</style>
</head>
<body>
<div id="rp" style="width:0%"></div>
<div id="eb"></div>
<header>
  <h1>&#128269; SRE Agent</h1>
  <span class="sdot" id="sdot"></span>
  <span id="cluster-name">&#8203;</span>
  <span id="last-check">&#8203;</span>
</header>
<div class="cards" id="cards"></div>
<div class="ctrl">
  <label>Window&nbsp;</label>
  <button class="btn" id="h0" onclick="setH(.25)">15m</button>
  <button class="btn on" id="h1" onclick="setH(1)">1h</button>
  <button class="btn" id="h3" onclick="setH(3)">3h</button>
  <button class="btn" id="h6" onclick="setH(6)">6h</button>
  <button class="btn" id="h12" onclick="setH(12)">12h</button>
  <button class="btn" id="h24" onclick="setH(24)">24h</button>
  &nbsp;
  <button class="btn sev-C on" id="sb-C" onclick="togS('C')">&#128308; Critical</button>
  <button class="btn sev-W on" id="sb-W" onclick="togS('W')">&#128993; Warning</button>
  <button class="btn sev-I on" id="sb-I" onclick="togS('I')">&#8505;&#65039; Info</button>
</div>
<!-- ── Issues ──────────────────────────────────────────────────────────── -->
<section>
  <h2>&#9888; Issues <span class="cnt" id="i-cnt"></span></h2>
  <div id="iss"></div>
</section>
<!-- ── Odoo Config Checks ─────────────────────────────────────────────── -->
<section>
  <h2>&#128336; Odoo Config Checks <span class="cnt" id="odoo-cnt"></span></h2>
  <div id="odoo"></div>
</section>
<!-- ── Nodes ──────────────────────────────────────────────────────────── -->
<section>
  <h2>&#128736; Nodes</h2>
  <div id="nds"></div>
</section>
<!-- ── K8s Events by namespace ────────────────────────────────────────── -->
<section>
  <h2>&#128203; K8s Events by Namespace <span class="cnt" id="ke-cnt"></span></h2>
  <div id="kevt"></div>
</section>
<!-- ── Node Scaling Events ────────────────────────────────────────────── -->
<section>
  <h2>&#128200; Node Scaling &amp; Status Events <span class="cnt" id="ne-cnt"></span></h2>
  <div id="nevt"></div>
</section>
<script>
var st={h:1,sv:{C:1,W:1,I:1},d:null,ne:[]};
var RSEC=60,_el=0;

/* ── helpers ──────────────────────────────────────────────────────────── */
function esc(v){return String(v===null||v===undefined?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmtTs(ts){return ts?ts.substring(0,19).replace('T',' ')+' UTC':'';}
function cutoff(){
  var now=new Date();
  now.setTime(now.getTime()-st.h*3600000);
  return now.toISOString().substring(0,19);   /* YYYY-MM-DDTHH:MM:SS */
}

/* ── window / severity filters ──────────────────────────────────────── */
function setH(h){
  st.h=h;
  ['h0','h1','h3','h6','h12','h24'].forEach(function(id){document.getElementById(id).classList.remove('on');});
  var m={0.25:'h0',1:'h1',3:'h3',6:'h6',12:'h12',24:'h24'};
  if(m[h])document.getElementById(m[h]).classList.add('on');
  /* re-render everything that uses the time window */
  renderIss();
  renderOdoo();
  renderKevt(st.d?st.d.issues:[]);
  fetch('/api/node-events?hours='+h).then(function(r){return r.json();}).then(function(ne){st.ne=ne;renderNE(ne);}).catch(function(){});
}
function togS(s){
  st.sv[s]=st.sv[s]?0:1;
  var b=document.getElementById('sb-'+s);
  if(b){b.classList.toggle('on',!!st.sv[s]);}
  renderIss();
  renderOdoo();
  renderKevt(st.d?st.d.issues:[]);
}

/* ── shared issue filter ─────────────────────────────────────────────── */
var SV_MAP={CRITICAL:'C',WARNING:'W',INFO:'I'};
function issInWindow(i){
  /* issues with a ts are time-stamped events → apply window filter.
     issues without a ts are "current state" checks → always show. */
  if(!i.ts) return true;
  return i.ts.substring(0,19)>=cutoff();
}
function issVisible(i,section){
  /* section: 'infra' | 'odoo' | 'event' */
  var isEvent=i.check.startsWith('Event:');
  var isOdoo=!!i.odoo;
  if(section==='infra'  && (isEvent||isOdoo)) return false;
  if(section==='odoo'   && !isOdoo)           return false;
  if(section==='event'  && !isEvent)           return false;
  var k=SV_MAP[i.severity]||'I';
  if(!st.sv[k]) return false;
  return issInWindow(i);
}

/* ── issue row builder ───────────────────────────────────────────────── */
function issRow(i){
  var tsCell=i.ts
    ?'<span class="ts-cell">'+esc(fmtTs(i.ts))+'</span>'+(i.age?'<br><span class="mu" style="font-size:10px">'+esc(i.age)+' ago</span>':'')
    :'<span class="cur-state">current state</span>';
  var recHtml='';
  if(i.action){
    recHtml='<div class="rec"><span class="rec-lbl">&#128295; Fix:</span>'+esc(i.action)+'</div>';
  }
  return '<tr>'+
    '<td class="sv-'+esc(i.severity)+' mono" style="white-space:nowrap">'+esc(i.severity)+'</td>'+
    '<td class="ts-cell">'+tsCell+'</td>'+
    '<td class="mono mu">'+esc(i.check)+'</td>'+
    '<td class="mono" style="color:var(--blu)">'+esc(i.resource)+'</td>'+
    '<td>'+esc(i.message)+recHtml+'</td>'+
    '</tr>';
}

/* ── render: header cards ─────────────────────────────────────────────── */
function renderCards(d){
  var s=d.summary||{};
  var ok=d.healthy;
  document.getElementById('sdot').className='sdot '+(ok?'sdot-ok':'sdot-err');
  document.getElementById('cluster-name').textContent=d.cluster||'—';
  document.getElementById('last-check').textContent='Last check: '+fmtTs(d.checked_at);
  var dur=d.check_duration?d.check_duration.toFixed(1)+'s':'—';
  document.getElementById('cards').innerHTML=
    '<div class="card c-crit"><div class="lbl">Critical</div><div class="val">'+(s.critical||0)+'</div></div>'+
    '<div class="card c-warn"><div class="lbl">Warning</div><div class="val">'+(s.warning||0)+'</div></div>'+
    '<div class="card c-info"><div class="lbl">Info</div><div class="val">'+(s.info||0)+'</div></div>'+
    '<div class="card c-node"><div class="lbl">Nodes</div><div class="val">'+((d.nodes_overview||[]).length)+'</div></div>'+
    '<div class="card c-dur"><div class="lbl">Duration</div><div class="val">'+dur+'</div></div>';
}

/* ── render: infra issues (no events, no odoo) ──────────────────────── */
function renderIss(){
  var d=st.d; if(!d)return;
  var iss=(d.issues||[]).filter(function(i){return issVisible(i,'infra');});
  var cnt=document.getElementById('i-cnt');
  if(cnt)cnt.textContent='('+iss.length+')';
  var el=document.getElementById('iss');
  if(!iss.length){el.innerHTML='<p class="empty">No issues in the selected window / severity filter.</p>';return;}
  var rows=iss.map(issRow);
  el.innerHTML='<table><thead><tr><th>Severity</th><th>Timestamp (UTC)</th><th>Check</th><th>Resource</th><th>Message</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>';
}

/* ── render: Odoo checks, grouped by namespace ───────────────────────── */
function renderOdoo(){
  var d=st.d; if(!d)return;
  var iss=(d.issues||[]).filter(function(i){return issVisible(i,'odoo');});
  var cnt=document.getElementById('odoo-cnt');
  if(cnt)cnt.textContent='('+iss.length+')';
  var el=document.getElementById('odoo');
  if(!iss.length){el.innerHTML='<p class="empty">No Odoo config issues found.</p>';return;}
  /* group by namespace (resource = "ns/deployment") */
  var groups={};
  var order=[];
  iss.forEach(function(i){
    var ns=i.resource.indexOf('/')>=0?i.resource.split('/')[0]:i.resource;
    if(!groups[ns]){groups[ns]=[];order.push(ns);}
    groups[ns].push(i);
  });
  var html='';
  order.forEach(function(ns){
    var rows=groups[ns].map(issRow).join('');
    html+='<div class="ns-group">'+
      '<div class="ns-hdr">&#128230; '+esc(ns)+'</div>'+
      '<table><thead><tr><th>Severity</th><th>Timestamp</th><th>Check</th><th>Resource</th><th>Message</th></tr></thead>'+
      '<tbody>'+rows+'</tbody></table></div>';
  });
  el.innerHTML=html;
}

/* ── render: K8s events, grouped by namespace ─────────────────────────── */
function renderKevt(allIssues){
  var iss=(allIssues||[]).filter(function(i){return issVisible(i,'event');});
  var cnt=document.getElementById('ke-cnt');
  if(cnt)cnt.textContent='('+iss.length+')';
  var el=document.getElementById('kevt');
  if(!iss.length){el.innerHTML='<p class="empty">No K8s events in the selected window.</p>';return;}
  /* group by namespace — resource is "kind/name" but we need ns from check = "Event:Reason" and resource field.
     The resource field for events is formatted as "Kind/name" within a namespace.
     We use the issue itself — namespace is embedded as the first component of resource when it contains '/'.
     For K8s events the resource is set to "ns/kind/name" or "kind/name" depending on the check.
     To be safe, extract the namespace from resource if it looks like "ns/..." else use "cluster-scoped". */
  var groups={};
  var order=[];
  iss.forEach(function(i){
    var parts=i.resource.split('/');
    /* heuristic: if first segment has no uppercase letters and isn't "Node", treat as namespace */
    var ns=(parts.length>=2&&parts[0]&&!/[A-Z]/.test(parts[0][0]))?parts[0]:'cluster-scoped';
    if(!groups[ns]){groups[ns]=[];order.push(ns);}
    groups[ns].push(i);
  });
  var html='';
  order.sort().forEach(function(ns){
    var rows=groups[ns].map(issRow).join('');
    html+='<div class="ns-group">'+
      '<div class="ns-hdr">&#128230; '+esc(ns)+'</div>'+
      '<table><thead><tr><th>Severity</th><th>Timestamp</th><th>Event</th><th>Resource</th><th>Message</th></tr></thead>'+
      '<tbody>'+rows+'</tbody></table></div>';
  });
  el.innerHTML=html;
}

/* ── render: nodes table ─────────────────────────────────────────────── */
function renderNodes(nodes){
  var el=document.getElementById('nds');
  if(!nodes||!nodes.length){el.innerHTML='<p class="empty">No node data.</p>';return;}
  var rows=nodes.map(function(n){
    var st2=n.ready?'<span class="rdy">&#10003; Ready</span>':'<span class="nrdy">&#10007; NotReady</span>';
    var p=[];
    if(n.disk_pressure)p.push('<span style="color:var(--red)" title="DiskPressure">&#128190;Disk</span>');
    if(n.mem_pressure) p.push('<span style="color:var(--yel)" title="MemoryPressure">&#129504;Mem</span>');
    if(n.pid_pressure) p.push('<span style="color:var(--yel)" title="PIDPressure">&#9888;PID</span>');
    var cpu=(n.cpu_alloc_m!=null&&n.cpu_alloc_m!==0)
      ?(n.cpu_alloc_m>=1000?(n.cpu_alloc_m/1000).toFixed(1)+' vCPU':n.cpu_alloc_m+' m')
      :'—';
    var mem=(n.mem_alloc_mi!=null&&n.mem_alloc_mi!==0)
      ?(n.mem_alloc_mi/1024).toFixed(1)+' Gi'
      :'—';
    return '<tr>'+
      '<td class="mono">'+esc(n.name)+'</td>'+
      '<td>'+st2+(p.length?' &nbsp;'+p.join(' '):'')+'</td>'+
      '<td class="mono mu">'+cpu+'</td>'+
      '<td class="mono mu">'+mem+'</td>'+
      '<td class="mono mu">'+esc(n.age||'—')+'</td>'+
      '</tr>';
  });
  el.innerHTML='<table><thead><tr><th>Node</th><th>Status</th><th>CPU Alloc</th><th>RAM Alloc</th><th>Age</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>';
}

/* ── render: node scaling events ─────────────────────────────────────── */
function renderNE(evts){
  var el=document.getElementById('nevt');
  var cnt=document.getElementById('ne-cnt');
  if(cnt)cnt.textContent='('+((evts||[]).length)+')';
  if(!evts||!evts.length){el.innerHTML='<p class="empty">No node events in the selected window.</p>';return;}
  var EM={NodeAdded:'ev-A',NodeRemoved:'ev-R',NodeNotReady:'ev-N',NodeRecovered:'ev-V'};
  var IC={NodeAdded:'&#43;',NodeRemoved:'&#8722;',NodeNotReady:'&#9888;',NodeRecovered:'&#10003;'};
  var rows=evts.slice().reverse().map(function(e){
    var cls=EM[e.type]||'';
    var ic=IC[e.type]||'&#8226;';
    return '<tr>'+
      '<td class="mono mu" style="white-space:nowrap">'+esc(fmtTs(e.ts))+'</td>'+
      '<td class="'+cls+'">'+ic+' '+esc(e.type)+'</td>'+
      '<td class="mono">'+esc(e.node)+'</td>'+
      '<td class="mono mu">'+esc(e.detail||'')+'</td>'+
      '</tr>';
  });
  el.innerHTML='<table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Node</th><th>Detail</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>';
}

/* ── main fetch ──────────────────────────────────────────────────────── */
function fetchAll(){
  fetch('/api/status').then(function(r){return r.json();}).then(function(d){
    st.d=d;
    renderCards(d);
    renderIss();
    renderOdoo();
    renderKevt(d.issues);
    renderNodes(d.nodes_overview);
    document.getElementById('eb').style.display='none';
  }).catch(function(e){
    var eb=document.getElementById('eb');
    eb.textContent='Failed to fetch /api/status: '+e;
    eb.style.display='block';
  });
  fetch('/api/node-events?hours='+st.h).then(function(r){return r.json();}).then(function(ne){st.ne=ne;renderNE(ne);}).catch(function(){});
}

/* ── progress bar + auto-refresh ─────────────────────────────────────── */
function tick(){
  _el++;
  var rp=document.getElementById('rp');
  if(rp)rp.style.width=Math.min(_el/RSEC*100,100)+'%';
  if(_el>=RSEC){fetchAll();_el=0;if(rp)rp.style.width='0%';}
}

fetchAll();
setInterval(tick,1000);
</script>
</body>
</html>
"""


# ╔══════════════════════════════════════════════════════════════════╗
# ║  HTTP SERVER  (/  /health  /api/*)                               ║
# ╚══════════════════════════════════════════════════════════════════╝

_agent_start_time = time.time()


class _WebHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        raw_path = self.path
        if "?" in raw_path:
            path, qs = raw_path.split("?", 1)
        else:
            path, qs = raw_path, ""
        params: Dict[str, str] = {}
        for part in qs.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                params[k] = v

        if path == "/":
            self._serve(_WEB_UI.encode("utf-8"), "text/html; charset=utf-8")

        elif path in ("/health", "/healthz"):
            snap = _data_store.latest()
            if snap:
                r  = snap["report"]
                ok = r.get("healthy", True)
                ts = r.get("checked_at", "")
                cl = r.get("cluster", CLUSTER_NAME)
            else:
                ok, ts, cl = True, "", CLUSTER_NAME
            body = json.dumps({"status": "ok", "cluster": cl,
                               "healthy": ok, "checked_at": ts}).encode()
            self._serve(body, "application/json")

        elif path == "/api/status":
            snap = _data_store.latest()
            if snap:
                r = dict(snap["report"])
                r["check_duration"] = snap["duration"]
                body = json.dumps(r, default=str).encode()
            else:
                body = json.dumps({"error": "no data yet — first check cycle pending"}).encode()
            self._serve(body, "application/json")

        elif path == "/api/history":
            try:
                h = float(params.get("hours", "1"))
            except ValueError:
                h = 1.0
            self._serve(json.dumps(_data_store.history(h), default=str).encode(), "application/json")

        elif path == "/api/node-events":
            try:
                h = float(params.get("hours", "6"))
            except ValueError:
                h = 6.0
            self._serve(json.dumps(_node_watcher.get_events(h), default=str).encode(), "application/json")

        else:
            self.send_response(404)
            self.end_headers()

    def _serve(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass   # suppress per-request access logs


def start_web_server():
    """Start the HTTP server (web UI + JSON API) in a daemon thread."""
    server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), _WebHandler)
    t = threading.Thread(target=server.serve_forever, name="web-http", daemon=True)
    t.start()
    print(
        f"[{_now().strftime('%Y-%m-%d %H:%M:%S UTC')}] "
        f"🌐 Web UI on :{HTTP_PORT}  "
        f"→ /  /health  /api/status  /api/history  /api/node-events"
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
        client.RbacAuthorizationV1Api(),
        client.NetworkingV1Api(),
        client.AutoscalingV2Api(),   # for Odoo HPA checks
    )


# ── Odoo config helpers ───────────────────────────────────────────────────────

def _parse_k8s_mem(s: str) -> int:
    """Parse K8s memory string to bytes.  '2.5Gi' → 2684354560, '512Mi' → 536870912"""
    if not s:
        return 0
    s = s.strip()
    for suffix, mult in [("Ki", 1024), ("Mi", 1024**2), ("Gi", 1024**3), ("Ti", 1024**4),
                         ("K",  1000), ("M",  1000**2),  ("G",  1000**3),  ("T",  1000**4)]:
        if s.endswith(suffix):
            try:
                return int(float(s[:-len(suffix)]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _parse_k8s_cpu(s: str) -> float:
    """Parse K8s CPU string to cores.  '500m' → 0.5,  '2' → 2.0"""
    if not s:
        return 0.0
    s = s.strip()
    if s.endswith("m"):
        try:
            return int(s[:-1]) / 1000.0
        except ValueError:
            return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def _gib(b: int) -> str:
    """Format bytes as 'X.XGiB' for display."""
    return f"{b / (1024**3):.2f} GiB"


def _parse_odoo_conf(text: str) -> Dict[str, str]:
    """Parse odoo.conf ini-style text into a lowercase key→value dict.

    Handles [section] headers, comments (#, ;), and bare key = value lines.
    """
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("["):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            result[key.strip().lower()] = val.strip()
    return result


def _find_odoo_configmaps(core: client.CoreV1Api, ns: str,
                           dep) -> List[Dict[str, str]]:
    """Return a list of parsed odoo.conf dicts found in ConfigMaps for this namespace.

    Search strategy (in order):
      1. ConfigMaps referenced in the deployment's envFrom / volumes
      2. All ConfigMaps in the namespace whose data contains Odoo config keys
    """
    _ODOO_KEYS = {"limit_memory_hard", "limit_memory_soft", "workers", "limit_time_cpu"}
    found: List[Dict[str, str]] = []
    seen_names: set = set()

    def _try_cm(name: str) -> None:
        if name in seen_names:
            return
        seen_names.add(name)
        try:
            cm = core.read_namespaced_config_map(name, ns)
        except ApiException:
            return
        for val in (cm.data or {}).values():
            parsed = _parse_odoo_conf(val)
            if _ODOO_KEYS & set(parsed):
                found.append(parsed)
                return

    # 1. From deployment spec
    try:
        for container in (dep.spec.template.spec.containers or []):
            for ef in (container.env_from or []):
                if ef.config_map_ref:
                    _try_cm(ef.config_map_ref.name)
        for vol in (dep.spec.template.spec.volumes or []):
            if vol.config_map:
                _try_cm(vol.config_map.name)
    except (AttributeError, TypeError):
        pass

    if found:
        return found

    # 2. Scan all ConfigMaps in the namespace
    try:
        cms = core.list_namespaced_config_map(ns, limit=100)
        for cm in cms.items:
            _try_cm(cm.metadata.name)
            if found:
                return found
    except ApiException:
        pass

    return found


def _is_odoo_deployment(dep) -> bool:
    """Heuristic: is this deployment an Odoo workload?"""
    name = (dep.metadata.name or "").lower()
    labels = dep.metadata.labels or {}
    label_vals = " ".join(str(v).lower() for v in labels.values())
    # Check name, labels, or container images
    if "odoo" in name:
        return True
    if "odoo" in label_vals:
        return True
    try:
        for c in dep.spec.template.spec.containers:
            if "odoo" in (c.image or "").lower():
                return True
    except (AttributeError, TypeError):
        pass
    return False

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
            "name":         name,
            "ready":        ready,
            "disk_pressure": disk_p,
            "mem_pressure":  mem_p,
            "pid_pressure":  pid_p,
            "cpu_alloc_m":  _cpu(alloc.get("cpu", "0")),
            "mem_alloc_mi": _mem(alloc.get("memory", "0")),
            "age":          _age(created),
            # CLI-only: ANSI-coloured flag strings for print_report
            "_flags":       flags,
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
    """Fetch Warning events, deduplicate, tag with time bucket and count.

    Time buckets (for display in print_report):
      ACTIVE  — last EVENTS_ACTIVE_MINS minutes  (🔴 happening right now)
      RECENT  — last EVENTS_RECENT_MINS minutes  (🟡 just happened)
      HISTORY — older, within EVENTS_LOOKBACK_H  (🔵 background context)
    """
    issues  = []
    now_dt  = _now()
    cutoff  = now_dt - timedelta(hours=EVENTS_LOOKBACK_H)
    active_cut = now_dt - timedelta(minutes=EVENTS_ACTIVE_MINS)
    recent_cut = now_dt - timedelta(minutes=EVENTS_RECENT_MINS)

    # Aggregate: (ns, obj, reason) → best representative event + summed count
    agg: Dict[tuple, Dict] = {}

    try:
        raw = core.list_event_for_all_namespaces(field_selector="type=Warning", limit=500)
    except ApiException:
        return []

    for ev in raw.items:
        ts = ev.last_timestamp
        if not ts:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue

        ns     = (ev.metadata.namespace or
                  (ev.involved_object.namespace if ev.involved_object else None) or "?")
        obj    = (ev.involved_object.name if ev.involved_object else None) or "?"
        kind   = ((ev.involved_object.kind if ev.involved_object else None) or "").lower()
        reason = ev.reason or "Unknown"
        msg    = (ev.message or "")[:200]
        count  = ev.count or 1

        key = (ns, obj, reason)
        if key in agg:
            agg[key]["count"] += count
            if ts > agg[key]["ts"]:
                agg[key]["ts"]  = ts
                agg[key]["msg"] = msg          # keep most recent message
        else:
            agg[key] = {"ns": ns, "obj": obj, "kind": kind,
                        "reason": reason, "msg": msg, "ts": ts, "count": count}

    # Sort most-recent first so ACTIVE events surface at top of their severity group
    for ev in sorted(agg.values(), key=lambda x: x["ts"], reverse=True):
        ns, obj, kind    = ev["ns"], ev["obj"], ev["kind"]
        reason, msg, ts  = ev["reason"], ev["msg"], ev["ts"]
        count            = ev["count"]

        resource_str = (f"{ns}/{obj}" if kind in
                        ("pod","deployment","replicaset","node","persistentvolumeclaim","")
                        else f"{ns}/{kind}/{obj}")

        if reason in ("Evicting","Evicted","OOMKilling","SystemOOM","FreeDiskSpaceFailed",
                      "NodeNotReady","NodeHasDiskPressure","NodeHasInsufficientMemory"):
            sev = "CRITICAL"
        elif reason in ("BackOff","Failed","FailedCreate","FailedMount","FailedScheduling",
                        "FailedKillPod","NetworkNotReady","Unhealthy","ProbeWarning",
                        "ImageGCFailed","EvictionThresholdMet","FailedCreatePodSandBox",
                        "FailedGetResourceMetric","FailedComputeMetricsReplicas"):
            sev = "WARNING"
        else:
            sev = "INFO"

        # Time bucket — used by print_report for colour-coded display
        if ts >= active_cut:
            bucket = "ACTIVE"
        elif ts >= recent_cut:
            bucket = "RECENT"
        else:
            bucket = "HISTORY"

        iss = _issue(sev, f"Event:{reason}", resource_str, msg, when=ts)
        iss["event_count"]  = count
        iss["event_bucket"] = bucket
        iss["event_object"] = obj
        iss["event_kind"]   = kind
        issues.append(iss)

    return issues


# ╔══════════════════════════════════════════════════════════════════╗
# ║  SCALING & INCIDENT ANALYSIS                                      ║
# ╚══════════════════════════════════════════════════════════════════╝

# Event reasons that indicate a scaling or scheduling event
_SCALING_REASONS = frozenset({
    "SuccessfulRescale",            # HPA scaled up or down
    "FailedGetResourceMetric",      # HPA can't get CPU/memory metrics
    "FailedComputeMetricsReplicas", # HPA can't compute target replicas
    "FailedScheduling",             # Scheduler can't place pod
    "Scheduled",                    # Pod finally placed on a node
    "TriggeredScaleUp",             # Cluster autoscaler adding a node
    "ScaleDown",                    # Cluster autoscaler removing a pod/node
    "ScalingReplicaSet",            # Deployment scaled a replica set
    "SuccessfulCreate",             # ReplicaSet created a pod
    "SuccessfulDelete",             # ReplicaSet deleted a pod
    "Killing",                      # Container/pod being stopped
    "FailedCreatePodSandBox",       # CNI/network sandbox failure (Flannel etc.)
    "Unhealthy",                    # Readiness/liveness probe failure during startup
    "TaintManagerEviction",         # Taint-based eviction or cancellation
})

# Display color per reason (sev string, ANSI color var)
_REASON_SEV = {
    "FailedScheduling":              ("WARNING",  Y),
    "FailedGetResourceMetric":       ("WARNING",  Y),
    "FailedComputeMetricsReplicas":  ("WARNING",  Y),
    "FailedCreatePodSandBox":        ("CRITICAL", R),
    "Unhealthy":                     ("WARNING",  Y),
    "SuccessfulRescale":             ("NORMAL",   G),
    "TriggeredScaleUp":              ("NORMAL",   G),
    "ScaleDown":                     ("NORMAL",   B),
    "Scheduled":                     ("NORMAL",   G),
    "ScalingReplicaSet":             ("NORMAL",   DM),
    "SuccessfulCreate":              ("NORMAL",   DM),
    "SuccessfulDelete":              ("NORMAL",   DM),
    "Killing":                       ("NORMAL",   DM),
    "TaintManagerEviction":          ("NORMAL",   DM),
}


def fetch_scaling_events(core: client.CoreV1Api,
                          app_namespaces: Optional[List[str]] = None) -> List[Dict]:
    """Fetch all scaling-related events for the last SCALING_HISTORY_H hours.

    Fetches both Normal and Warning events, then filters by _SCALING_REASONS.
    Returns a list sorted by timestamp (oldest first).
    Each entry: ts, ts_str, age, type, reason, ns, obj, kind, message, count.
    """
    cutoff = _now() - timedelta(hours=SCALING_HISTORY_H)
    results: List[Dict] = []
    seen: Set[tuple] = set()

    for ev_type in ("Warning", "Normal"):
        try:
            resp = core.list_event_for_all_namespaces(
                field_selector=f"type={ev_type}", limit=600)
            raw = resp.items
        except ApiException:
            continue

        for ev in raw:
            reason = ev.reason or ""
            if reason not in _SCALING_REASONS:
                continue

            ts = ev.last_timestamp or ev.first_timestamp or ev.metadata.creation_timestamp
            if not ts:
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue

            ns = (ev.metadata.namespace
                  or (ev.involved_object.namespace if ev.involved_object else None)
                  or "?")
            if app_namespaces and ns not in app_namespaces:
                continue

            obj = (ev.involved_object.name if ev.involved_object else None) or "?"
            key = (ns, obj, reason, ts.strftime("%Y%m%d%H%M"))
            if key in seen:
                continue
            seen.add(key)

            results.append({
                "ts":      ts,
                "ts_str":  ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "age":     _age(ts),
                "type":    ev_type,
                "reason":  reason,
                "ns":      ns,
                "obj":     obj,
                "kind":    (ev.involved_object.kind if ev.involved_object else "") or "",
                "message": (ev.message or "")[:250],
                "count":   ev.count or 1,
            })

    results.sort(key=lambda x: x["ts"])
    return results


def get_hpa_status() -> List[Dict]:
    """Fetch current HPA status for all non-system namespaces.

    Tries AutoscalingV2 first, falls back to V1.
    Returns a list of HPA info dicts.
    """
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

    results: List[Dict] = []

    for api_cls, use_v2 in [(client.AutoscalingV2Api, True),
                             (client.AutoscalingV1Api, False)]:
        try:
            api = api_cls()
            hpas = api.list_horizontal_pod_autoscaler_for_all_namespaces(limit=100)
        except Exception:
            continue

        for hpa in hpas.items:
            ns   = hpa.metadata.namespace
            name = hpa.metadata.name
            if ns in SKIP_NS:
                continue

            cur = hpa.status.current_replicas or 0
            des = hpa.status.desired_replicas or 0
            mn  = hpa.spec.min_replicas or 1
            mx  = hpa.spec.max_replicas or 0

            metrics_ok    = True
            metric_lines: List[str] = []
            conditions:   List[str] = []

            if use_v2:
                for cond in (hpa.status.conditions or []):
                    if cond.type == "ScalingActive" and cond.status != "True":
                        metrics_ok = False
                        conditions.append(
                            f"ScalingActive=False: {(cond.message or '')[:120]}")
                    elif cond.type == "AbleToScale" and cond.status != "True":
                        conditions.append(
                            f"AbleToScale=False: {(cond.message or '')[:120]}")

                for cm in (hpa.status.current_metrics or []):
                    if cm.type == "Resource" and cm.resource:
                        rname = cm.resource.name
                        cv, tv = "?", "?"
                        if cm.resource.current:
                            if cm.resource.current.average_utilization:
                                cv = f"{cm.resource.current.average_utilization}%"
                            elif cm.resource.current.average_value:
                                cv = str(cm.resource.current.average_value)
                        for sm in (hpa.spec.metrics or []):
                            if (sm.type == "Resource" and sm.resource
                                    and sm.resource.name == rname):
                                t = sm.resource.target
                                if t.average_utilization:
                                    tv = f"{t.average_utilization}%"
                                elif t.average_value:
                                    tv = str(t.average_value)
                        metric_lines.append(f"{rname}: {cv}/{tv}")

            if not metric_lines:
                metric_lines = ["? (no current metrics reported)"]
                metrics_ok = False

            results.append({
                "ns":         ns,
                "name":       name,
                "current":    cur,
                "desired":    des,
                "min":        mn,
                "max":        mx,
                "metrics":    metric_lines,
                "metrics_ok": metrics_ok,
                "conditions": conditions,
            })
        break  # success on first API version that works

    return results


def detect_incidents(events: List[Dict]) -> List[Dict]:
    """Scan the event timeline and identify known problematic scaling patterns.

    Detected patterns:
      HPAFlapping     — scale-up then scale-down within 15 min
      CNINotReady     — FailedCreatePodSandBox with Flannel/subnet.env error
      HPAMetricLag    — 2+ consecutive FailedGetResourceMetric for same HPA
      NodeScaleDelay  — TriggeredScaleUp followed by persistent FailedScheduling

    Returns a list of incident dicts sorted by ts.
    """
    incidents: List[Dict] = []
    by_ns: Dict[str, List[Dict]] = {}
    for ev in events:
        by_ns.setdefault(ev["ns"], []).append(ev)

    for ns, ns_evs in by_ns.items():

        # ── Pattern 1: HPAFlapping ───────────────────────────────────────────
        rescales = sorted([e for e in ns_evs if e["reason"] == "SuccessfulRescale"],
                          key=lambda x: x["ts"])
        scale_ups   = [e for e in rescales if "above target" in e["message"].lower()]
        scale_downs = [e for e in rescales if ("below target" in e["message"].lower()
                                                or "all metrics below" in e["message"].lower())]
        for su in scale_ups:
            for sd in scale_downs:
                delta = sd["ts"] - su["ts"]
                if timedelta(seconds=0) < delta < timedelta(minutes=15):
                    dm = max(1, int(delta.total_seconds() / 60))
                    incidents.append({
                        "type":     "HPAFlapping",
                        "ns":       ns,
                        "severity": "WARNING",
                        "msg":      (f"HPA scaled up then scaled back down in {dm}m. "
                                     f"New pod was not ready in time (large image pull or new node "
                                     f"spin-up delay) — metrics fell below threshold before the pod "
                                     f"could serve traffic."),
                        "ts": su["ts"],
                    })
                    break  # one incident per scale-up event

        # ── Pattern 2: CNI not ready on newly autoscaled node ────────────────
        cni_fails = [e for e in ns_evs
                     if e["reason"] == "FailedCreatePodSandBox"
                     and ("flannel"     in e["message"].lower()
                          or "subnet.env" in e["message"].lower()
                          or "cni"        in e["message"].lower())]
        if cni_fails:
            incidents.append({
                "type":     "CNINotReady",
                "ns":       ns,
                "severity": "CRITICAL",
                "msg":      (f"Pod sandbox creation failed for {cni_fails[0]['obj']}: "
                             f"Flannel CNI not yet initialized on newly autoscaled node. "
                             f"/run/flannel/subnet.env was missing — node joined the cluster "
                             f"before Flannel finished its startup."),
                "ts": cni_fails[0]["ts"],
            })

        # ── Pattern 3: HPA metric lag ────────────────────────────────────────
        mfails = [e for e in ns_evs
                  if e["reason"] in ("FailedGetResourceMetric",
                                     "FailedComputeMetricsReplicas")]
        if len(mfails) >= 2:
            first = min(mfails, key=lambda x: x["ts"])
            last  = max(mfails, key=lambda x: x["ts"])
            dm    = max(1, int((last["ts"] - first["ts"]).total_seconds() / 60))
            hpa_names = ", ".join({e["obj"] for e in mfails})
            incidents.append({
                "type":     "HPAMetricLag",
                "ns":       ns,
                "severity": "WARNING",
                "msg":      (f"HPA '{hpa_names}' had no metrics for ~{dm}m. "
                             f"Metrics-server lost sight of pod after reschedule (IP changed). "
                             f"HPA cannot make any scaling decisions during this window."),
                "ts": first["ts"],
            })

        # ── Pattern 4: Node scale-up too slow ────────────────────────────────
        trigger = next((e for e in ns_evs if e["reason"] == "TriggeredScaleUp"), None)
        if trigger:
            late_fails = [e for e in ns_evs
                          if e["reason"] == "FailedScheduling"
                          and e["ts"] > trigger["ts"]
                          and (e["ts"] - trigger["ts"]) > timedelta(minutes=1)]
            if late_fails:
                dm = max(1, int((late_fails[-1]["ts"] - trigger["ts"]).total_seconds() / 60))
                incidents.append({
                    "type":     "NodeScaleDelay",
                    "ns":       ns,
                    "severity": "WARNING",
                    "msg":      (f"Cluster autoscaler triggered node scale-up but pod "
                                 f"remained unschedulable for {dm}m. "
                                 f"OKE node provisioning (VM boot → kubelet → Flannel) "
                                 f"takes 2–5 min — pods stay Pending for this entire window."),
                    "ts": trigger["ts"],
                })

    incidents.sort(key=lambda x: x["ts"])
    return incidents


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


# ── Security checks ──────────────────────────────────────────────────────────

# Env-var names that hint at a secret being hardcoded in plain text
_SECRET_ENV_PAT = re.compile(
    r'(password|passwd|secret|token|api.?key|auth|credential|private.?key|'
    r'access.?key|client.?secret|db.?pass|database.?pass|encryption.?key)',
    re.IGNORECASE
)

# Linux capabilities that significantly expand container privileges
_DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "SYS_BOOT", "NET_RAW", "DAC_OVERRIDE",
    "DAC_READ_SEARCH", "SETUID", "SETGID",
})

# hostPath prefixes that expose sensitive host filesystem areas
_SENSITIVE_HOST_PATHS = ("/var/run/docker.sock",
                         "/etc", "/proc", "/sys", "/root", "/boot",
                         "/var/lib/docker", "/run/containerd")


def check_pod_security(pod_items: list) -> List[Dict]:
    """Security posture checks based on Kubernetes Goat scenarios (sc-1,2,4,11,16,20).

    Checks per pod/container:
      - PrivilegedContainer    (CRITICAL) — securityContext.privileged:true
      - DockerSocketMount      (CRITICAL) — /var/run/docker.sock hostPath
      - DangerousHostPath      (CRITICAL) — /etc, /proc, /sys etc. hostPath
      - HostNetworkPod         (WARNING)  — hostNetwork:true
      - HostPIDPod             (WARNING)  — hostPID:true
      - HostIPCPod             (WARNING)  — hostIPC:true
      - DangerousCapability    (WARNING)  — SYS_ADMIN, NET_ADMIN, etc.
      - HardcodedSecret        (CRITICAL) — plain-text secret in env var
      - ContainerRunsAsRoot    (INFO)     — no runAsNonRoot / runAsUser
      - AutomountSAToken       (INFO)     — default SA with token automounted
    """
    issues = []

    for pod in pod_items:
        ns   = pod.metadata.namespace
        name = pod.metadata.name
        spec = pod.spec

        if ns in SKIP_NS:
            continue
        if pod.status.phase not in ("Running", "Pending", "Unknown"):
            continue

        res = f"{ns}/{name}"

        # ── Pod-level host namespace flags ───────────────────────────────────
        if getattr(spec, 'host_network', False):
            issues.append(_issue("WARNING", "HostNetworkPod", res,
                "Pod uses hostNetwork:true — bypasses pod network isolation, sees all node interfaces",
                action=f"Remove hostNetwork:true from pod spec in {ns}"))

        if getattr(spec, 'host_pid', False):
            issues.append(_issue("WARNING", "HostPIDPod", res,
                "Pod uses hostPID:true — can inspect and signal all host processes",
                action=f"Remove hostPID:true from pod spec in {ns}"))

        if getattr(spec, 'host_ipc', False):
            issues.append(_issue("WARNING", "HostIPCPod", res,
                "Pod uses hostIPC:true — shares host IPC namespace (shared-memory attack surface)",
                action=f"Remove hostIPC:true from pod spec in {ns}"))

        # ── automount default SA token ────────────────────────────────────────
        sa   = (getattr(spec, 'service_account_name', None) or 'default')
        auto = getattr(spec, 'automount_service_account_token', True)
        if sa == 'default' and auto is not False:
            issues.append(_issue("INFO", "AutomountSAToken", res,
                "Pod uses default ServiceAccount with automounted token — unnecessary K8s API access if compromised",
                action=f"Add automountServiceAccountToken: false to the pod spec in {ns}"))

        # ── hostPath volumes ─────────────────────────────────────────────────
        for vol in (spec.volumes or []):
            if not vol.host_path:
                continue
            hp = (vol.host_path.path or "").rstrip("/")
            if hp == "/var/run/docker.sock":
                issues.append(_issue("CRITICAL", "DockerSocketMount", res,
                    f"Volume '{vol.name}' mounts /var/run/docker.sock — full container-to-host escape",
                    action=f"Remove docker socket volume from {ns}/{name} immediately"))
            elif any(hp == p or hp.startswith(p + "/") for p in _SENSITIVE_HOST_PATHS if p != "/var/run/docker.sock"):
                issues.append(_issue("CRITICAL", "DangerousHostPath", res,
                    f"Volume '{vol.name}' mounts sensitive host path '{hp}'",
                    action=f"Replace hostPath with emptyDir or ConfigMap in {ns}/{name}"))

        # ── Per-container checks ─────────────────────────────────────────────
        all_containers = list(spec.containers or []) + list(spec.init_containers or [])
        for c in all_containers:
            cn = c.name
            sc = c.security_context

            # Privileged
            if sc and getattr(sc, 'privileged', False):
                issues.append(_issue("CRITICAL", "PrivilegedContainer", res,
                    f"Container '{cn}' runs privileged — full host escape possible",
                    action=f"kubectl set env deployment/<name> -n {ns} — remove privileged:true"))

            # Running as root (no runAsNonRoot, no runAsUser != 0)
            runs_as_root = True
            if sc:
                if getattr(sc, 'run_as_non_root', None):
                    runs_as_root = False
                uid = getattr(sc, 'run_as_user', None)
                if uid is not None and uid != 0:
                    runs_as_root = False
            # Only flag if capabilities are also not dropped
            if runs_as_root:
                drops_all = False
                if sc and sc.capabilities:
                    drops_all = any(
                        (d or "").upper() == "ALL" for d in (sc.capabilities.drop or [])
                    )
                if not drops_all:
                    issues.append(_issue("INFO", "ContainerRunsAsRoot", res,
                        f"Container '{cn}' has no runAsNonRoot/runAsUser — likely running as UID 0",
                        action=f"Add securityContext.runAsNonRoot: true, runAsUser: 1000 to '{cn}'"))

            # Dangerous Linux capabilities
            if sc and sc.capabilities:
                for cap in (sc.capabilities.add or []):
                    if (cap or "").upper() in _DANGEROUS_CAPS:
                        issues.append(_issue("WARNING", "DangerousCapability", res,
                            f"Container '{cn}' adds capability {cap.upper()} — elevated kernel access",
                            action=f"Remove cap {cap} from {cn} or use 'drop: [ALL], add: [<min-needed>]'"))

            # Hardcoded secrets in env vars
            for env in (c.env or []):
                if (env.value and not env.value_from
                        and len(env.value) > 3
                        and _SECRET_ENV_PAT.search(env.name or "")):
                    issues.append(_issue("CRITICAL", "HardcodedSecret", res,
                        f"Container '{cn}' env '{env.name}' has a plain-text value — use secretKeyRef",
                        action=(f"kubectl create secret generic <name> --from-literal={env.name}=<value> "
                                f"-n {ns} && update deployment to use secretKeyRef")))

    return issues


def check_rbac(rbac_api) -> List[Dict]:
    """Detect overly permissive RBAC roles/bindings (Kubernetes Goat sc-16).

    Checks:
      - RBACWildcardRole         (CRITICAL) — ClusterRole/Role with wildcard verbs or resources
      - RBACClusterAdminBinding  (CRITICAL) — ServiceAccount outside system NS bound to cluster-admin
    """
    issues = []

    # Built-in roles we don't want to flag
    _BUILTIN = {"cluster-admin", "admin", "edit", "view",
                "system:aggregate-to-admin", "system:aggregate-to-edit",
                "system:aggregate-to-view"}

    # ClusterRoles with wildcards
    try:
        for cr in rbac_api.list_cluster_role(limit=200).items:
            name = cr.metadata.name
            if name.startswith("system:") or name in _BUILTIN:
                continue
            for rule in (cr.rules or []):
                verbs = rule.verbs or []
                resources = rule.resources or []
                if "*" in verbs or "*" in resources:
                    which = "verbs+resources" if ("*" in verbs and "*" in resources) \
                            else ("verbs" if "*" in verbs else "resources")
                    issues.append(_issue("CRITICAL", "RBACWildcardRole", f"clusterrole/{name}",
                        f"ClusterRole '{name}' has wildcard {which} — unrestricted cluster-wide access",
                        action=f"kubectl describe clusterrole {name}  # replace wildcards with specific rules"))
                    break  # one issue per role is enough
    except ApiException:
        pass

    # Namespace Roles with wildcard verbs AND resources
    try:
        for role in rbac_api.list_role_for_all_namespaces(limit=300).items:
            ns   = role.metadata.namespace
            name = role.metadata.name
            if ns in SKIP_NS:
                continue
            for rule in (role.rules or []):
                verbs = rule.verbs or []
                resources = rule.resources or []
                if "*" in verbs and "*" in resources:
                    issues.append(_issue("WARNING", "RBACWildcardRole", f"{ns}/role/{name}",
                        f"Role '{name}' in ns '{ns}' grants wildcard verbs on wildcard resources",
                        action=f"kubectl describe role {name} -n {ns}"))
                    break
    except ApiException:
        pass

    # ClusterRoleBindings to cluster-admin by app service accounts
    _SYSTEM_NS = {"kube-system", "monitoring", "cert-manager", "ingress-nginx", "sre-agent"}
    try:
        for crb in rbac_api.list_cluster_role_binding(limit=200).items:
            if crb.role_ref.name != "cluster-admin":
                continue
            for subj in (crb.subjects or []):
                if subj.kind == "ServiceAccount":
                    sns = subj.namespace or "unknown"
                    if sns not in _SYSTEM_NS:
                        issues.append(_issue("CRITICAL", "RBACClusterAdminBinding",
                            f"clusterrolebinding/{crb.metadata.name}",
                            f"ServiceAccount '{subj.name}' in ns '{sns}' is bound to cluster-admin",
                            action=f"kubectl describe clusterrolebinding {crb.metadata.name}"))
    except ApiException:
        pass

    return issues


def check_network_policies(core, networking_api, pod_items: list) -> List[Dict]:
    """Flag namespaces with running pods but zero NetworkPolicy (Kubernetes Goat sc-20).

    Accepts the pre-fetched pod_items list from run_all_checks() to avoid
    a redundant list_pod_for_all_namespaces() API call.

    Checks:
      - NoNetworkPolicy  (INFO) — namespace has pods but no network segmentation
    """
    issues = []
    try:
        ns_items = core.list_namespace(limit=100).items
    except Exception:
        return issues

    try:
        all_netpols = networking_api.list_network_policy_for_all_namespaces(limit=300).items
        ns_with_policy = {np.metadata.namespace for np in all_netpols}
    except Exception:
        ns_with_policy = set()

    # Build set of namespaces that have at least one Running pod from pre-fetched data
    ns_with_pods: Set[str] = {
        pod.metadata.namespace
        for pod in pod_items
        if (pod.status.phase or "") == "Running" and pod.metadata.namespace
    }

    for ns_obj in ns_items:
        ns = ns_obj.metadata.name
        if ns in SKIP_NS:
            continue
        if ns in ns_with_pods and ns not in ns_with_policy:
            issues.append(_issue("INFO", "NoNetworkPolicy", f"namespace/{ns}",
                f"Namespace '{ns}' has running pods but no NetworkPolicy — flat network, all pods reachable",
                action=f"kubectl apply a default-deny-ingress NetworkPolicy in namespace {ns}"))

    return issues


def check_nodeport_services(core) -> List[Dict]:
    """Flag services of type NodePort that may unintentionally expose ports on node IPs (Goat sc-8).

    Checks:
      - NodePortExposed  (WARNING) — NodePort service outside known infrastructure namespaces
    """
    issues = []
    # Namespaces where NodePort/LoadBalancer is intentional (infra, monitoring)
    _INFRA_NS = {"monitoring", "ingress-nginx", "kube-system", "cert-manager"}

    try:
        svcs = core.list_service_for_all_namespaces(limit=200).items
    except Exception:
        return issues

    for svc in svcs:
        ns   = svc.metadata.namespace
        name = svc.metadata.name
        if ns in SKIP_NS or ns in _INFRA_NS:
            continue
        stype = (svc.spec.type or "ClusterIP")
        if stype == "NodePort":
            ports = [str(p.node_port) for p in (svc.spec.ports or []) if p.node_port]
            issues.append(_issue("WARNING", "NodePortExposed", f"{ns}/{name}",
                f"Service '{name}' type=NodePort (node ports: {', '.join(ports) or '?'}) — "
                f"exposed on every node's IP, bypasses Ingress/WAF",
                action=f"Switch to ClusterIP + Ingress. Temp mitigation: restrict via OCI NSG rules."))

    return issues


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ODOO CONFIG CHECKS  (Ladder of Limits)                          ║
# ╚══════════════════════════════════════════════════════════════════╝

def check_odoo_config(core: client.CoreV1Api,
                      apps: client.AppsV1Api,
                      autoscaling: client.AutoscalingV2Api) -> List[Dict]:
    """Verify Odoo memory/worker config aligns with K8s resources and HPA settings.

    Ladder of Limits:
        Soft limit  →  HPA trigger  →  K8s Request  →  Hard limit  →  K8s Limit

    Key invariants:
        hard  = 80% of K8s limit      (Odoo kills worker before OOM eviction)
        soft  = 80% of K8s request    (Odoo gracefully restarts within guaranteed memory)
        HPA memory target ≈ soft / request × 100  (scale-out triggered at soft limit)
        workers = max(1, floor(cpu_request × 2))
    """
    issues: List[Dict] = []

    # Discover all namespaces dynamically — skip system namespaces
    _SKIP_NS = {"kube-system", "kube-public", "kube-node-lease",
                "sre-agent", "monitoring", "cert-manager",
                "ingress-nginx", "nfs", "falco", "trivy", "trivy-system"}
    try:
        all_ns = [n.metadata.name for n in core.list_namespace(limit=200).items
                  if n.metadata.name not in _SKIP_NS]
    except ApiException:
        all_ns = []

    for ns in all_ns:
        # ── Fetch deployments ────────────────────────────────────────────────
        try:
            deploys = apps.list_namespaced_deployment(ns, limit=50).items
        except ApiException:
            continue

        odoo_deploys = [d for d in deploys if _is_odoo_deployment(d)]
        if not odoo_deploys:
            continue

        # ── Fetch HPAs in namespace (once, keyed by target deployment name) ──
        hpa_map: Dict[str, Any] = {}
        try:
            for h in autoscaling.list_namespaced_horizontal_pod_autoscaler(ns, limit=50).items:
                ref = h.spec.scale_target_ref
                if ref and ref.kind == "Deployment":
                    hpa_map[ref.name] = h
        except ApiException:
            pass

        for dep in odoo_deploys:
            dep_name = dep.metadata.name
            rid      = f"{ns}/{dep_name}"

            # ── K8s resource limits for the first Odoo container ────────────
            containers = (dep.spec.template.spec.containers or [])
            container  = next(
                (c for c in containers if "odoo" in (c.name or "").lower()),
                containers[0] if containers else None,
            )
            if container is None:
                continue

            res    = container.resources or type("R", (), {"requests": {}, "limits": {}})()
            reqs   = res.requests or {}
            lims   = res.limits   or {}
            k8s_req_mem = _parse_k8s_mem(reqs.get("memory", ""))
            k8s_lim_mem = _parse_k8s_mem(lims.get("memory", ""))
            k8s_req_cpu = _parse_k8s_cpu(reqs.get("cpu", ""))

            # ── Find & parse Odoo ConfigMap ──────────────────────────────────
            conf_list = _find_odoo_configmaps(core, ns, dep)
            if not conf_list:
                issues.append(_issue("INFO", "OdooConfigNotFound", rid,
                    f"No odoo.conf ConfigMap found for deployment '{dep_name}'. "
                    f"Ladder-of-Limits compliance cannot be verified. "
                    f"Mount a ConfigMap containing limit_memory_hard / workers etc."))
                continue

            conf = conf_list[0]   # use first match (typically only one)

            # Parse integer/float values with safe fallback
            def _ci(key: str, default: int = 0) -> int:
                try:
                    return int(float(conf.get(key, default) or default))
                except (ValueError, TypeError):
                    return default

            def _cf(key: str, default: float = 0.0) -> float:
                try:
                    return float(conf.get(key, default) or default)
                except (ValueError, TypeError):
                    return default

            hard          = _ci("limit_memory_hard")
            soft          = _ci("limit_memory_soft")
            workers       = _ci("workers")
            limit_request = _ci("limit_request")
            time_cpu      = _ci("limit_time_cpu")
            time_real     = _ci("limit_time_real")
            logfile       = conf.get("logfile", "").strip().lower()

            # ── HPA for this deployment ──────────────────────────────────────
            hpa = hpa_map.get(dep_name)
            hpa_mem_pct:  int = 0
            hpa_cpu_pct:  int = 0
            hpa_max:      int = 0
            hpa_sd_secs:  int = 300   # default stabilization window
            if hpa:
                hpa_max = hpa.spec.max_replicas or 0
                for m in (hpa.spec.metrics or []):
                    if m.type == "Resource" and m.resource:
                        t = m.resource.target
                        if m.resource.name == "memory" and t and t.average_utilization:
                            hpa_mem_pct = t.average_utilization
                        if m.resource.name == "cpu" and t and t.average_utilization:
                            hpa_cpu_pct = t.average_utilization
                try:
                    sd = hpa.spec.behavior.scale_down
                    if sd and sd.stabilization_window_seconds is not None:
                        hpa_sd_secs = sd.stabilization_window_seconds
                except AttributeError:
                    pass

            # ════════════════════════════════════════════════════════════════
            #  MEMORY LADDER CHECKS
            # ════════════════════════════════════════════════════════════════

            # 1. hard vs K8s limit
            if hard and k8s_lim_mem:
                ratio = hard / k8s_lim_mem
                if hard > k8s_lim_mem:
                    rec_hard = int(k8s_lim_mem * 0.80)
                    issues.append(_issue("CRITICAL", "OdooHardExceedsK8sLimit", rid,
                        f"limit_memory_hard={_gib(hard)} ({int(hard):,} bytes) > "
                        f"K8s limit={_gib(k8s_lim_mem)} ({int(k8s_lim_mem):,} bytes) "
                        f"→ pod OOMKilled before graceful worker restart. "
                        f"Recommended hard = {_gib(rec_hard)} ({rec_hard:,} bytes)"))
                elif ratio > 0.90:
                    rec_hard = int(k8s_lim_mem * 0.85)
                    issues.append(_issue("WARNING", "OdooHardTooCloseToLimit", rid,
                        f"limit_memory_hard={_gib(hard)} ({int(hard):,} bytes) is "
                        f"{ratio*100:.0f}% of K8s limit={_gib(k8s_lim_mem)} ({int(k8s_lim_mem):,} bytes) "
                        f"(<10% buffer). Transient spikes will OOMKill the pod. "
                        f"Target ≤85% → {_gib(rec_hard)} ({rec_hard:,} bytes)"))
                elif ratio < 0.70:
                    rec_hard = int(k8s_lim_mem * 0.80)
                    issues.append(_issue("WARNING", "OdooHardRatioLow", rid,
                        f"limit_memory_hard={_gib(hard)} ({int(hard):,} bytes) is only "
                        f"{ratio*100:.0f}% of K8s limit={_gib(k8s_lim_mem)} ({int(k8s_lim_mem):,} bytes). "
                        f"Workers restarting too early — wasting memory. "
                        f"Target ≥70–80% → {_gib(rec_hard)} ({rec_hard:,} bytes)"))

            # 2. soft vs hard (order check — highest priority)
            if soft and hard:
                if soft >= hard:
                    rec_soft = int(k8s_req_mem * 0.80) if k8s_req_mem else int(hard * 0.80)
                    issues.append(_issue("CRITICAL", "OdooSoftExceedsHard", rid,
                        f"limit_memory_soft={_gib(soft)} ({int(soft):,} bytes) ≥ "
                        f"limit_memory_hard={_gib(hard)} ({int(hard):,} bytes) "
                        f"→ graceful restart never triggered; every termination is abrupt. "
                        f"Set soft < hard. Recommended soft = {_gib(rec_soft)} ({rec_soft:,} bytes)"))

            # 3. soft vs K8s request
            if soft and k8s_req_mem:
                ratio_s = soft / k8s_req_mem
                if soft > k8s_req_mem:
                    rec_soft = int(k8s_req_mem * 0.80)
                    issues.append(_issue("WARNING", "OdooSoftExceedsRequest", rid,
                        f"limit_memory_soft={_gib(soft)} ({int(soft):,} bytes) > "
                        f"K8s request={_gib(k8s_req_mem)} ({int(k8s_req_mem):,} bytes) "
                        f"→ workers restart beyond guaranteed allocation. "
                        f"Recommended soft ≤ {_gib(rec_soft)} ({rec_soft:,} bytes)"))
                elif ratio_s < 0.60:
                    rec_soft = int(k8s_req_mem * 0.80)
                    issues.append(_issue("WARNING", "OdooSoftRatioLow", rid,
                        f"limit_memory_soft={_gib(soft)} ({int(soft):,} bytes) is only "
                        f"{ratio_s*100:.0f}% of K8s request={_gib(k8s_req_mem)} ({int(k8s_req_mem):,} bytes) "
                        f"→ excessive worker churn. "
                        f"Target 75–80% → {_gib(rec_soft)} ({rec_soft:,} bytes)"))

            # ════════════════════════════════════════════════════════════════
            #  WORKER COUNT CHECK
            # ════════════════════════════════════════════════════════════════
            if workers == 0:
                issues.append(_issue("CRITICAL", "WorkersMissing", rid,
                    f"workers=0 → Odoo running in single-process mode. "
                    f"No parallelism; one slow request blocks all others. "
                    f"Set workers={max(1, int(k8s_req_cpu * 2))} (2 per CPU core)"))
            elif k8s_req_cpu:
                expected = max(1, int(k8s_req_cpu * 2))
                if workers != expected:
                    issues.append(_issue("WARNING", "WorkerCountMismatch", rid,
                        f"workers={workers} but cpu_request={k8s_req_cpu:.2g} → "
                        f"expected workers={expected} (rule: 2 per CPU core). "
                        f"{'Too many: context-switch overhead, excess memory.' if workers > expected else 'Too few: CPU underutilised.'}"))

            # ════════════════════════════════════════════════════════════════
            #  HPA CHECKS
            # ════════════════════════════════════════════════════════════════
            if not hpa:
                issues.append(_issue("WARNING", "HpaNotFound", rid,
                    f"No HPA found for deployment '{dep_name}'. "
                    f"No auto-scaling — a single pod handles all traffic. "
                    f"Create HPA with memory=80%, cpu=75%, maxReplicas≥5."))
            else:
                # maxReplicas
                if hpa_max and hpa_max < 3:
                    issues.append(_issue("WARNING", "HpaMaxTooLow", rid,
                        f"HPA maxReplicas={hpa_max} — very limited scaling headroom. "
                        f"Recommended ≥5. "
                        f"kubectl patch hpa <name> -n {ns} -p '{{\"spec\":{{\"maxReplicas\":5}}}}'"))

                # memory alignment
                if hpa_mem_pct and soft and k8s_req_mem:
                    hpa_trigger = int(hpa_mem_pct / 100 * k8s_req_mem)
                    ideal_pct   = round(soft / k8s_req_mem * 100)
                    deviation   = abs(hpa_trigger - soft) / soft
                    if deviation > 0.20:
                        issues.append(_issue("WARNING", "HpaMemoryMisaligned", rid,
                            f"HPA memory target {hpa_mem_pct}% × request={_gib(k8s_req_mem)} "
                            f"triggers at {_gib(hpa_trigger)} ({hpa_trigger:,} bytes), "
                            f"but soft limit is {_gib(soft)} ({int(soft):,} bytes) "
                            f"(deviation {deviation*100:.0f}%). "
                            f"Set averageUtilization={ideal_pct} to align HPA trigger with soft limit."))

                # cpu target
                if hpa_cpu_pct and hpa_cpu_pct > 85:
                    issues.append(_issue("WARNING", "HpaCpuTargetHigh", rid,
                        f"HPA CPU target={hpa_cpu_pct}% — pods run near saturation before scale-out. "
                        f"Recommended ≤75%. Lower the target to allow faster response to spikes."))

                # scale-down window
                if hpa_sd_secs < 120:
                    issues.append(_issue("WARNING", "HpaScaleDownFast", rid,
                        f"HPA scaleDown.stabilizationWindowSeconds={hpa_sd_secs}s (<120s). "
                        f"Scale-down too aggressive — may cause oscillation (scale-up/down thrashing). "
                        f"Recommended ≥300s."))

            # ════════════════════════════════════════════════════════════════
            #  MISCELLANEOUS CONFIG CHECKS
            # ════════════════════════════════════════════════════════════════
            if limit_request and limit_request < 4096:
                issues.append(_issue("WARNING", "LimitRequestTooLow", rid,
                    f"limit_request={limit_request} — workers restart after {limit_request} requests (very frequent). "
                    f"Recommended: 8192. High churn causes warm-up overhead and transient errors."))

            if time_cpu == 0 or time_real == 0:
                missing = []
                if time_cpu == 0:  missing.append("limit_time_cpu")
                if time_real == 0: missing.append("limit_time_real")
                issues.append(_issue("INFO", "LimitTimeMissing", rid,
                    f"{', '.join(missing)} not set or zero → unlimited request duration. "
                    f"Runaway requests can lock workers indefinitely. "
                    f"Recommended: limit_time_cpu=600, limit_time_real=1200"))

            if logfile and logfile not in ("false", "0", "", "none"):
                issues.append(_issue("WARNING", "LogfileEnabled", rid,
                    f"logfile={conf.get('logfile', '')} — logs written to file instead of stdout. "
                    f"K8s cannot collect file logs via kubectl logs. "
                    f"Set logfile = False to stream logs to stdout."))

    return issues


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ORCHESTRATOR                                                    ║
# ╚══════════════════════════════════════════════════════════════════╝

_SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

def run_all_checks() -> Tuple[Dict[str, Any], float]:
    """Returns (report_dict, duration_seconds)."""
    t0 = time.time()
    core, apps, batch, rbac, networking, autoscaling = _clients()
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
        ("Nodes",           check_nodes,             (node_items,)),
        ("Pods",            check_pods,              (pod_items,)),
        ("Events",          check_events,            (core,)),
        ("PVCs",            check_pvcs,              (core,)),
        ("DaemonSets",      check_daemonsets,        (apps,)),
        ("StatefulSets",    check_statefulsets,      (apps,)),
        ("Jobs",            check_jobs,              (batch,)),
        ("Services",        check_services,          (core,)),
        ("ReplicaSets",     check_replicasets,       (apps,)),
        ("Deployments",     check_deployments,       (apps,)),
        ("Overcommit",      check_overcommit,        (node_items, pod_items)),
        # ── Security checks (Kubernetes Goat) ───────────────────────────────
        ("PodSecurity",     check_pod_security,      (pod_items,)),
        ("RBAC",            check_rbac,              (rbac,)),
        ("NetworkPolicies", check_network_policies,  (core, networking, pod_items)),
        ("NodePortServices",check_nodeport_services, (core,)),
        # ── Odoo Ladder-of-Limits compliance ────────────────────────────────
        ("OdooConfig",      check_odoo_config,       (core, apps, autoscaling)),
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

    # ── Enrich issues: backfill action from _REC, tag Odoo issues ─────────────
    _ODOO_CHECK_NAMES = {
        "OdooConfigNotFound",  "OdooHardExceedsK8sLimit", "OdooHardTooCloseToLimit",
        "OdooHardRatioLow",    "OdooSoftExceedsHard",     "OdooSoftExceedsRequest",
        "OdooSoftRatioLow",    "WorkersMissing",           "WorkerCountMismatch",
        "HpaNotFound",         "HpaMaxTooLow",             "HpaMemoryMisaligned",
        "HpaCpuTargetHigh",    "HpaScaleDownFast",         "LimitRequestTooLow",
        "LimitTimeMissing",    "LogfileEnabled",
    }
    for iss in all_issues:
        if "action" not in iss:
            rec = _REC.get(iss["check"])
            if rec:
                iss["action"] = rec["immediate"]
        if iss["check"] in _ODOO_CHECK_NAMES:
            iss["odoo"] = True

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
        cpu    = f"cpu:{nd['cpu_alloc_m']}m"
        mem    = f"mem:{nd['mem_alloc_mi']}Mi"
        flags  = ("  " + "  ".join(nd["_flags"])) if nd.get("_flags") else ""
        print(f"  {name} {status} │ {DM}{cpu:12}{RS} │ {DM}{mem:16}{RS} │ {DM}age:{nd['age']}{RS}{flags}")

    # ── Issues ─────────────────────────────────────────────────────────────────
    # Sort events within each severity: ACTIVE → RECENT → HISTORY
    _BUCKET_ORDER = {"ACTIVE": 0, "RECENT": 1, "HISTORY": 2, "": 3}
    issues = sorted(
        issues,
        key=lambda x: (
            _SEV_ORDER.get(x.get("severity", "INFO"), 3),
            _BUCKET_ORDER.get(x.get("event_bucket", ""), 3),
        )
    )

    def _print_section(sev: str, label: str, color: str):
        filtered = [i for i in issues if i["severity"] == sev]
        if not filtered:
            return
        print(f"\n{BD}{color}{'─'*W72}")
        print(f" {label} ({len(filtered)}){RS}")
        print(f"{BD}{color}{'─'*W72}{RS}")
        for iss in filtered:
            is_event = iss["check"].startswith("Event:")

            # Time string
            if "ts" in iss and "age" in iss:
                time_str = f"{DM}[{iss['ts']}]  ({iss['age']} ago){RS}"
            elif "age" in iss:
                time_str = f"{DM}(age: {iss['age']}){RS}"
            else:
                time_str = ""

            # Bucket badge + count (events only)
            badge = ""
            if is_event:
                bkt = iss.get("event_bucket", "")
                cnt = iss.get("event_count", 1)
                if bkt == "ACTIVE":
                    badge = f"  {R}{BD}● ACTIVE{RS}"
                elif bkt == "RECENT":
                    badge = f"  {Y}● RECENT{RS}"
                elif bkt == "HISTORY":
                    badge = f"  {DM}· HISTORY{RS}"
                if cnt > 1:
                    badge += f"  {BD}×{cnt}{RS}"

            check_col = f"{BD}{color}{iss['check']:<28}{RS}"
            res_col   = f"{C}{iss['resource']}{RS}"
            print(f"  {check_col} {res_col}{badge}")
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
# ║  SCALING INCIDENT PRINTER                                         ║
# ╚══════════════════════════════════════════════════════════════════╝

def _wrap(text: str, width: int = 70, indent: str = "") -> List[str]:
    """Word-wrap text into lines of at most `width` chars."""
    words, lines, line = text.split(), [], []
    for w in words:
        if len(" ".join(line + [w])) > width and line:
            lines.append(indent + " ".join(line))
            line = [w]
        else:
            line.append(w)
    if line:
        lines.append(indent + " ".join(line))
    return lines or [indent]


def print_scaling_report(events: List[Dict], hpa_statuses: List[Dict],
                          incidents: List[Dict], node_items: list):
    """Print the two-part scaling incident analysis.

    PART 1 — Historical events (older than SCALING_RECENT_MINS)
    PART 2 — Current events   (last SCALING_RECENT_MINS minutes)
    Plus: root-cause summary, HPA status, node schedulability.
    """
    recent_cutoff = _now() - timedelta(minutes=SCALING_RECENT_MINS)
    now_str = _now().strftime("%Y-%m-%d %H:%M:%S UTC")

    print()
    print(_line("━"))
    print(f"{BD}{W}  🔍  SCALING INCIDENT ANALYSIS  │  {CLUSTER_NAME}  │  {now_str}{RS}")
    print(_line("━"))
    print(f"\n  {DM}History window : {SCALING_HISTORY_H}h   "
          f"│  Recent window : last {SCALING_RECENT_MINS} min   "
          f"│  Scaling events found : {len(events)}{RS}\n")

    # ── Root Cause Summary ─────────────────────────────────────────────────────
    print(f"{BD}{DM}{'─'*W72}{RS}")
    print(f" {BD}🔎  ROOT CAUSE SUMMARY{RS}")
    print(f"{BD}{DM}{'─'*W72}{RS}")
    if incidents:
        for inc in incidents:
            col   = R if inc["severity"] == "CRITICAL" else Y
            ts_s  = inc["ts"].strftime("%H:%M UTC")
            print(f"\n  {col}{BD}{inc['type']:<22}{RS}  "
                  f"{C}{inc['ns']}{RS}  {DM}[{ts_s}  {_age(inc['ts'])} ago]{RS}")
            for ln in _wrap(inc["msg"], 68, "  " + " " * 24):
                print(f"{DM}{ln}{RS}")
            rec = _REC.get(inc["type"])
            if rec:
                print(f"\n  {'':24}{Y}⚡ Immediate:{RS} "
                      f"{DM}{rec['immediate'][:160]}{RS}")
                print(f"  {'':24}{G}🛡  Prevent: {RS} "
                      f"{DM}{rec['prevent'][:160]}{RS}")
        print()
    else:
        print(f"  {G}No known incident patterns detected in the last {SCALING_HISTORY_H}h.{RS}\n")

    # ── Event list helper ──────────────────────────────────────────────────────
    COL_TS  = 24   # "[YYYY-MM-DD HH:MM:SS UTC]"
    COL_AGE = 9    # "(99m ago)"
    COL_SEV = 9    # "CRITICAL "
    COL_RSN = 28   # reason

    def _print_event_list(ev_list: List[Dict], header: str, hdr_color: str):
        print(f"\n{BD}{hdr_color}{'─'*W72}")
        print(f" {header}  ({len(ev_list)} events){RS}")
        print(f"{BD}{hdr_color}{'─'*W72}{RS}")
        if not ev_list:
            print(f"  {DM}(none){RS}\n")
            return
        for ev in ev_list:
            sev, col = _REASON_SEV.get(ev["reason"], ("NORMAL", DM))
            if sev in ("CRITICAL", "WARNING"):
                sev_s = f"{col}{BD}{sev:<8}{RS}"
            else:
                sev_s = f"{DM}{'':8}{RS}"
            reason_s  = f"{col}{BD}{ev['reason']:<28}{RS}"
            count_s   = f" (×{ev['count']})" if ev["count"] > 1 else ""
            obj_s     = f"{C}{ev['ns']}/{ev['obj']}{RS}"
            ts_s      = f"{DM}[{ev['ts_str']}]  ({ev['age']:>5} ago){RS}"

            print(f"  {ts_s}")
            print(f"  {sev_s}  {reason_s}  {obj_s}")
            # Word-wrap the message
            msg = (ev["message"] + count_s)
            for ln in _wrap(msg, 66, "  " + " " * 10):
                print(f"{DM}{ln}{RS}")
            print()

    hist = [e for e in events if e["ts"] <  recent_cutoff]
    curr = [e for e in events if e["ts"] >= recent_cutoff]

    _print_event_list(
        hist,
        f"PART 1 — HISTORICAL EVENTS  (older than {SCALING_RECENT_MINS} min)",
        DM,
    )
    _print_event_list(
        curr,
        f"PART 2 — CURRENT EVENTS  (last {SCALING_RECENT_MINS} min)",
        Y,
    )

    # ── HPA Current Status ─────────────────────────────────────────────────────
    if hpa_statuses:
        print(f"{BD}{C}{'─'*W72}")
        print(f" HPA CURRENT STATUS{RS}")
        print(f"{BD}{C}{'─'*W72}{RS}")
        for h in hpa_statuses:
            ok_s = f"{G}✅ metrics OK{RS}" if h["metrics_ok"] else f"{Y}⚠  metrics UNAVAILABLE{RS}"
            print(f"\n  {BD}{h['ns']}/{h['name']}{RS}  "
                  f"{DM}current:{h['current']}  desired:{h['desired']}  "
                  f"min:{h['min']}  max:{h['max']}{RS}   {ok_s}")
            for m in h["metrics"]:
                print(f"    {DM}├ {m}{RS}")
            for cnd in h["conditions"]:
                print(f"    {Y}└ {cnd}{RS}")
        print()

    # ── Node schedulability overview ───────────────────────────────────────────
    if node_items:
        print(f"{BD}{B}{'─'*W72}")
        print(f" NODES & SCHEDULABILITY{RS}")
        print(f"{BD}{B}{'─'*W72}{RS}")
        now_ts = _now()
        for node in node_items:
            nname = node.metadata.name
            conds = {c.type: c.status for c in (node.status.conditions or [])}
            ready = conds.get("Ready") == "True"
            ready_s = f"{G}Ready    {RS}" if ready else f"{R}NOT READY{RS}"

            taints = node.spec.taints or []
            no_s = [t for t in taints if t.effect in ("NoSchedule", "NoExecute")]
            pref = [t for t in taints if t.effect == "PreferNoSchedule"]
            if no_s:
                taint_s = (f"  {Y}[NoSchedule: "
                           + ", ".join(f"{t.key}={t.value}" for t in no_s)
                           + f"]{RS}")
            elif pref:
                taint_s = (f"  {DM}[PreferNoSchedule: "
                           + ", ".join(f"{t.key}" for t in pref)
                           + f"]{RS}")
            else:
                taint_s = ""

            created = node.metadata.creation_timestamp
            new_flag = ""
            if created:
                age_sec = (now_ts - created.replace(tzinfo=timezone.utc)).total_seconds()
                if age_sec < 1800:  # joined <30 min ago
                    new_flag = f"  {G}{BD}[RECENTLY ADDED — {int(age_sec/60)}m ago]{RS}"

            alloc = node.status.allocatable or {}
            cpu_m  = _cpu(alloc.get("cpu",    "0"))
            mem_mi = _mem(alloc.get("memory", "0"))
            age_s  = _age(created) if created else "?"

            print(f"  {nname:<16}  {ready_s}  "
                  f"{DM}cpu:{cpu_m:>5}m  mem:{mem_mi:>6}Mi  age:{age_s}{RS}"
                  f"{taint_s}{new_flag}")
        print()

    print(_line("━"))
    print(f"  {DM}Run again: python agent.py --incidents  │  "
          f"History: SCALING_HISTORY_HOURS={SCALING_HISTORY_H}  "
          f"Recent: SCALING_RECENT_MINUTES={SCALING_RECENT_MINS}{RS}")
    print(_line("━"))
    print()


# ╔══════════════════════════════════════════════════════════════════╗
# ║  EVENT TIMELINE  (--events mode)                                  ║
# ╚══════════════════════════════════════════════════════════════════╝

def fetch_all_events(core: client.CoreV1Api,
                     lookback_h: int = None,
                     namespace_filter: Optional[str] = None) -> List[Dict]:
    """Fetch and aggregate ALL events (Warning + Normal) for the timeline view.

    Aggregates by (ns, obj, reason): sums counts, keeps min(first_ts)/max(last_ts).
    Skips system namespaces unless explicitly filtered in.
    Returns a list sorted by last_ts descending (most recent first).

    Each entry:
        ns, obj, kind, reason, ev_type, message,
        first_ts, last_ts, last_ts_str, last_age,
        count, duration_str, bucket
    """
    if lookback_h is None:
        lookback_h = SCALING_HISTORY_H

    now_dt     = _now()
    cutoff     = now_dt - timedelta(hours=lookback_h)
    active_cut = now_dt - timedelta(minutes=EVENTS_ACTIVE_MINS)
    recent_cut = now_dt - timedelta(minutes=EVENTS_RECENT_MINS)

    # (ns, obj, reason) → aggregated entry
    agg: Dict[tuple, Dict] = {}

    for ev_type in ("Warning", "Normal"):
        try:
            resp = core.list_event_for_all_namespaces(
                field_selector=f"type={ev_type}", limit=600)
        except ApiException:
            continue

        for ev in resp.items:
            last_ts = ev.last_timestamp or ev.first_timestamp or ev.metadata.creation_timestamp
            if not last_ts:
                continue
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            if last_ts < cutoff:
                continue

            ns = (ev.metadata.namespace
                  or (ev.involved_object.namespace if ev.involved_object else None)
                  or "?")

            # Namespace filter: if specified, skip others; otherwise skip system NS
            if namespace_filter:
                if ns != namespace_filter:
                    continue
            else:
                if ns in SKIP_NS:
                    continue

            obj    = (ev.involved_object.name    if ev.involved_object else None) or "?"
            kind   = (ev.involved_object.kind    if ev.involved_object else None) or ""
            reason = ev.reason or "Unknown"
            msg    = (ev.message or "")[:250]
            count  = ev.count or 1

            first_ts = ev.first_timestamp or last_ts
            if first_ts.tzinfo is None:
                first_ts = first_ts.replace(tzinfo=timezone.utc)

            key = (ns, obj, reason)
            if key in agg:
                agg[key]["count"] += count
                if last_ts > agg[key]["last_ts"]:
                    agg[key]["last_ts"] = last_ts
                    agg[key]["message"] = msg
                if first_ts < agg[key]["first_ts"]:
                    agg[key]["first_ts"] = first_ts
            else:
                agg[key] = {
                    "ns":       ns,      "obj":      obj,
                    "kind":     kind,    "reason":   reason,
                    "ev_type":  ev_type, "message":  msg,
                    "first_ts": first_ts,"last_ts":  last_ts,
                    "count":    count,
                }

    results = []
    for ev in agg.values():
        last_ts  = ev["last_ts"]
        first_ts = ev["first_ts"]
        dur_sec  = (last_ts - first_ts).total_seconds()
        dur_min  = int(dur_sec / 60)

        if last_ts >= active_cut:
            bucket = "ACTIVE"
        elif last_ts >= recent_cut:
            bucket = "RECENT"
        else:
            bucket = "HISTORY"

        ev["last_ts_str"]   = last_ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        ev["last_age"]      = _age(last_ts)
        ev["duration_str"]  = f"over {dur_min}m" if dur_min > 1 else ""
        ev["bucket"]        = bucket
        results.append(ev)

    results.sort(key=lambda x: x["last_ts"], reverse=True)
    return results


def print_events_report(events: List[Dict],
                         namespace_filter: Optional[str] = None,
                         lookback_h: int = None):
    """Print the three-bucket cluster event timeline.

    🔴 ACTIVE  — last EVENTS_ACTIVE_MINS min  (things happening right now)
    🟡 RECENT  — EVENTS_ACTIVE_MINS to EVENTS_RECENT_MINS min ago
    🔵 HISTORY — EVENTS_RECENT_MINS min to lookback_h hours ago

    Within each bucket events are grouped by namespace, then sorted
    Warning-first, most-recent first.
    """
    if lookback_h is None:
        lookback_h = SCALING_HISTORY_H

    now_str    = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
    ns_label   = f"ns: {namespace_filter}" if namespace_filter else "all namespaces"
    warn_total = sum(1 for e in events if e["ev_type"] == "Warning")
    norm_total = sum(1 for e in events if e["ev_type"] == "Normal")

    print()
    print(_line("━"))
    print(f"{BD}{W}  📋  CLUSTER EVENTS  │  {CLUSTER_NAME}  │  {now_str}{RS}")
    print(_line("━"))
    print(f"\n  {DM}Lookback : {lookback_h}h   │  Filter : {ns_label}   │  "
          f"Events : {len(events)}  "
          f"({Y}{warn_total} ⚠ Warning{RS}{DM}, {norm_total} Normal){RS}\n")

    # ── Namespace summary table ────────────────────────────────────────────────
    if not namespace_filter and events:
        ns_stats: Dict[str, Dict] = {}
        for ev in events:
            ns = ev["ns"]
            st = ns_stats.setdefault(ns, {"warn": 0, "norm": 0, "last_ts": None, "bucket": "HISTORY"})
            if ev["ev_type"] == "Warning":
                st["warn"] += 1
            else:
                st["norm"] += 1
            if st["last_ts"] is None or ev["last_ts"] > st["last_ts"]:
                st["last_ts"] = ev["last_ts"]
                st["bucket"]  = ev["bucket"]

        print(f"{BD}{DM}{'─'*W72}{RS}")
        print(f" {BD}NAMESPACE SUMMARY{RS}")
        print(f"{BD}{DM}{'─'*W72}{RS}")
        for ns, st in sorted(ns_stats.items(),
                              key=lambda x: (-x[1]["warn"], -(x[1]["norm"]))):
            if st["bucket"] == "ACTIVE":
                bkt_s = f"{R}{BD}● ACTIVE{RS}"
            elif st["bucket"] == "RECENT":
                bkt_s = f"{Y}● RECENT{RS}"
            else:
                bkt_s = f"{DM}· quiet  {RS}"
            warn_s = f"{Y}{st['warn']:>2} ⚠ Warning{RS}" if st["warn"] else f"{DM} 0 Warning{RS}"
            norm_s = f"{DM}{st['norm']:>2} Normal{RS}"
            age_s  = f"last event: {_age(st['last_ts'])}" if st["last_ts"] else ""
            print(f"  {ns:<22}  {bkt_s}  {warn_s}  {norm_s}  {DM}{age_s}{RS}")
        print()

    # ── Bucket printer ─────────────────────────────────────────────────────────
    def _print_bucket(bucket_name: str, icon: str, hdr_col: str,
                       time_desc: str, ev_list: List[Dict]):
        print(f"{BD}{hdr_col}{'━'*W72}")
        print(f" {icon}  {bucket_name}  —  {time_desc}  ({len(ev_list)} events){RS}")
        print(f"{BD}{hdr_col}{'━'*W72}{RS}")

        if not ev_list:
            print(f"\n  {G}✓ Nothing here — all quiet.{RS}\n")
            return

        # Group by namespace, warnings first
        by_ns: Dict[str, List[Dict]] = {}
        for ev in ev_list:
            by_ns.setdefault(ev["ns"], []).append(ev)

        for ns, ns_evs in sorted(by_ns.items(),
                                  key=lambda x: -sum(1 for e in x[1] if e["ev_type"]=="Warning")):
            ns_warn = sum(1 for e in ns_evs if e["ev_type"] == "Warning")
            ns_icon = f"{Y}⚠{RS}" if ns_warn else f"{DM}·{RS}"
            if len(by_ns) > 1:
                print(f"\n  {ns_icon} {BD}{C}{ns}{RS}  "
                      f"{DM}({ns_warn} Warning, {len(ns_evs)-ns_warn} Normal){RS}")

            # Sort: warnings first, then most-recent first
            sorted_evs = sorted(
                ns_evs,
                key=lambda e: (0 if e["ev_type"] == "Warning" else 1, -e["last_ts"].timestamp())
            )

            for ev in sorted_evs:
                is_warn  = ev["ev_type"] == "Warning"
                col      = Y if is_warn else DM
                type_ico = f"{Y}⚠{RS}" if is_warn else f"{DM}·{RS}"
                cnt_s    = f"  {BD}×{ev['count']}{RS}" if ev["count"] > 1 else ""
                dur_s    = f"  {DM}{ev['duration_str']}{RS}" if ev["duration_str"] else ""

                print(f"\n    {DM}[{ev['last_ts_str']}]  ({ev['last_age']:>5} ago){RS}"
                      f"{cnt_s}{dur_s}")
                print(f"    {type_ico} {col}{BD}{ev['reason']:<28}{RS}  "
                      f"{W}{ev['obj']}{RS}  {DM}({ev['kind'].lower() or 'object'}){RS}")
                # Word-wrap message
                for ln in _wrap(ev["message"], 64, "      "):
                    print(f"{DM}{ln}{RS}")
        print()

    active_evs  = [e for e in events if e["bucket"] == "ACTIVE"]
    recent_evs  = [e for e in events if e["bucket"] == "RECENT"]
    history_evs = [e for e in events if e["bucket"] == "HISTORY"]

    _print_bucket("ACTIVE",  "🔴", R,
                  f"last {EVENTS_ACTIVE_MINS} min — things happening RIGHT NOW",
                  active_evs)
    _print_bucket("RECENT",  "🟡", Y,
                  f"{EVENTS_ACTIVE_MINS}–{EVENTS_RECENT_MINS} min ago",
                  recent_evs)
    _print_bucket("HISTORY", "🔵", DM,
                  f"{EVENTS_RECENT_MINS} min – {lookback_h}h ago",
                  history_evs)

    print(_line("━"))
    print(f"  {DM}Flags: --events [--ns <namespace>]  │  "
          f"EVENTS_ACTIVE_MINUTES={EVENTS_ACTIVE_MINS}  "
          f"EVENTS_RECENT_MINUTES={EVENTS_RECENT_MINS}  "
          f"SCALING_HISTORY_HOURS={lookback_h}{RS}")
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
                                    "text": f"_…and {len(issues)-15} more issues. Check the web UI (:8080) or run kubectl._"}})
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
    _data_store.add(report, duration)
    print_report(report)
    send_slack(report)
    return report


def run_loop():
    ts_start = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts_start}] SRE Agent v4 started — cluster: {CLUSTER_NAME}  interval: {CHECK_INTERVAL}s")

    while True:
        try:
            report, duration = run_all_checks()
            _data_store.add(report, duration)

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
    # ── Parse shared flags ─────────────────────────────────────────────────────
    # --ns <namespace>  : filter events/incidents to a single namespace
    # --hours <N>       : override lookback window (default: SCALING_HISTORY_HOURS)
    _ns_filter: Optional[str] = None
    _lookback_h: int = SCALING_HISTORY_H
    for _i, _a in enumerate(sys.argv):
        if _a == "--ns" and _i + 1 < len(sys.argv):
            _ns_filter = sys.argv[_i + 1]
        elif _a.startswith("--ns="):
            _ns_filter = _a.split("=", 1)[1]
        elif _a == "--hours" and _i + 1 < len(sys.argv):
            try: _lookback_h = int(sys.argv[_i + 1])
            except ValueError: pass
        elif _a.startswith("--hours="):
            try: _lookback_h = int(_a.split("=", 1)[1])
            except ValueError: pass

    if "--events" in sys.argv:
        # ── Event timeline mode ────────────────────────────────────────────────
        # Usage:
        #   python agent.py --events
        #   python agent.py --events --ns rohama
        #   python agent.py --events --ns rohama --hours 12
        #   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --events --ns rohama
        #
        # Shows three time buckets:
        #   🔴 ACTIVE  — last EVENTS_ACTIVE_MINUTES  (default 5 min)
        #   🟡 RECENT  — last EVENTS_RECENT_MINUTES  (default 30 min)
        #   🔵 HISTORY — up to SCALING_HISTORY_HOURS (default 6h)
        # Events grouped by namespace, warnings first, with repeat counts.
        ts = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
        ns_msg = f"  ns={_ns_filter}" if _ns_filter else "  all namespaces"
        print(f"\n[{ts}] 📋 SRE Agent — Event Timeline{ns_msg}  lookback={_lookback_h}h")

        core, *_ = _clients()
        events   = fetch_all_events(core, lookback_h=_lookback_h,
                                     namespace_filter=_ns_filter)
        print_events_report(events, namespace_filter=_ns_filter, lookback_h=_lookback_h)

    elif "--incidents" in sys.argv:
        # ── Scaling / incident analysis mode ──────────────────────────────────
        # Usage:
        #   python agent.py --incidents
        #   SCALING_HISTORY_HOURS=12 python agent.py --incidents
        #   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --incidents
        #
        # Shows a two-part report:
        #   Part 1 — historical scaling events (older than SCALING_RECENT_MINUTES)
        #   Part 2 — current / live events     (last SCALING_RECENT_MINUTES)
        # Plus: auto-detected incident patterns, HPA status, node schedulability.
        ts = _now().strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"\n[{ts}] 🔍 SRE Agent — Scaling Incident Analysis")
        print(f"[{ts}]    History  : {SCALING_HISTORY_H}h   "
              f"│  Recent window : {SCALING_RECENT_MINS} min")

        core, apps, batch, rbac, networking, autoscaling = _clients()

        try:
            node_items = core.list_node(limit=100).items
        except Exception as e:
            print(f"[{ts}] ⚠  Could not list nodes: {e}", file=sys.stderr)
            node_items = []

        print(f"[{ts}]    Fetching scaling events …")
        events      = fetch_scaling_events(core)
        hpa_stats   = get_hpa_status()
        incidents   = detect_incidents(events)

        print_scaling_report(events, hpa_stats, incidents, node_items)

    elif "--odoo" in sys.argv:
        # ── Odoo Config Health report ──────────────────────────────────────────
        # Usage:
        #   python agent.py --odoo
        #   python agent.py --odoo --ns awqaf          # single namespace
        #   kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --odoo
        #
        # Prints a full ladder-of-limits compliance report for every Odoo deployment:
        #   🔴 CRITICAL  — OOMKill-risk misconfigs
        #   🟡 WARNING   — alignment issues
        #   ℹ  INFO      — advisory items
        # Each issue shows the deployment, message, and recommended fix.
        ts = _now().strftime("%Y-%m-%d %H:%M:%S UTC")

        W  = "\033[33m"; R = "\033[31m"; B = "\033[34m"
        G  = "\033[32m"; C = "\033[36m"; RS = "\033[0m"; BOLD = "\033[1m"

        _ODOO_CHECKS = {
            "OdooHardExceedsK8sLimit", "OdooHardTooCloseToLimit", "OdooHardRatioLow",
            "OdooSoftExceedsHard",     "OdooSoftExceedsRequest",  "OdooSoftRatioLow",
            "WorkersMissing",          "WorkerCountMismatch",
            "HpaNotFound",             "HpaMemoryMisaligned",     "HpaMaxTooLow",
            "HpaCpuTargetHigh",        "HpaScaleDownFast",
            "LimitRequestTooLow",      "LimitTimeMissing",
            "LogfileEnabled",          "OdooConfigNotFound",
        }

        SEV_COLOR  = {"CRITICAL": R, "WARNING": W, "INFO": B}
        SEV_EMOJI  = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "ℹ "}
        SEV_ORDER  = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

        print(f"\n{BOLD}{'─'*72}{RS}")
        print(f"{BOLD}  Odoo Config Health Report{RS}   {ts}")
        if _ns_filter:
            print(f"  Namespace filter: {C}{_ns_filter}{RS}")
        print(f"{BOLD}{'─'*72}{RS}\n")

        core, apps, _, _, _, autoscaling = _clients()
        issues = check_odoo_config(core, apps, autoscaling)

        # Filter by namespace if --ns provided
        if _ns_filter:
            issues = [i for i in issues if i["resource"].startswith(_ns_filter + "/")]

        # Filter to Odoo checks only (exclude any bleed-through)
        issues = [i for i in issues if i["check"] in _ODOO_CHECKS]
        issues.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 3), x["resource"], x["check"]))

        if not issues:
            print(f"  {G}✅  No Odoo config issues found.{RS}\n")
        else:
            # ── Summary counts ─────────────────────────────────────────────
            n_crit = sum(1 for i in issues if i["severity"] == "CRITICAL")
            n_warn = sum(1 for i in issues if i["severity"] == "WARNING")
            n_info = sum(1 for i in issues if i["severity"] == "INFO")
            n_dep  = len({i["resource"] for i in issues})
            print(f"  {R}{BOLD}{n_crit} CRITICAL{RS}  "
                  f"{W}{BOLD}{n_warn} WARNING{RS}  "
                  f"{B}{n_info} INFO{RS}  "
                  f"across {BOLD}{n_dep}{RS} deployment(s)\n")

            # ── Group by severity, then deployment ─────────────────────────
            current_sev = None
            for iss in issues:
                sev  = iss["severity"]
                col  = SEV_COLOR.get(sev, "")
                em   = SEV_EMOJI.get(sev, "•")
                dep  = iss["resource"]       # "namespace/deployment"
                chk  = iss["check"]
                msg  = iss["message"]
                rec  = _REC.get(chk, {})

                if sev != current_sev:
                    label = {"CRITICAL": "CRITICAL — OOMKill Risk",
                             "WARNING":  "WARNING  — Misalignment",
                             "INFO":     "INFO     — Advisory"}.get(sev, sev)
                    print(f"{col}{BOLD}{'─'*72}")
                    print(f"  {em}  {label}{RS}")
                    print(f"{col}{BOLD}{'─'*72}{RS}\n")
                    current_sev = sev

                print(f"  {col}{BOLD}{chk:<32}{RS}  {C}{dep}{RS}")
                # Wrap message at 68 chars
                for line in _wrap(msg, 66):
                    print(f"    {line}")
                if rec:
                    print(f"    {W}⚡ Fix : {RS}{_wrap(rec.get('immediate',''), 60)[0] if rec.get('immediate') else ''}")
                    if len(_wrap(rec.get('immediate',''), 60)) > 1:
                        for line in _wrap(rec.get('immediate',''), 60)[1:]:
                            print(f"           {line}")
                    print(f"    {B}🛡 Prevent: {RS}{_wrap(rec.get('prevent',''), 58)[0] if rec.get('prevent') else ''}")
                print()

        # ── Per-deployment summary table ───────────────────────────────────
        print(f"{BOLD}{'─'*72}{RS}")
        print(f"{BOLD}  Deployment Summary{RS}")
        print(f"{BOLD}{'─'*72}{RS}")
        print(f"  {'Namespace/Deployment':<40}  {'CRIT':>4}  {'WARN':>4}  {'INFO':>4}")
        print(f"  {'─'*40}  {'────':>4}  {'────':>4}  {'────':>4}")

        from collections import defaultdict
        dep_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"CRITICAL":0,"WARNING":0,"INFO":0})
        for iss in issues:
            dep_counts[iss["resource"]][iss["severity"]] += 1

        for dep in sorted(dep_counts):
            c = dep_counts[dep]
            crit_s = f"{R}{c['CRITICAL']:>4}{RS}" if c["CRITICAL"] else f"{'0':>4}"
            warn_s = f"{W}{c['WARNING']:>4}{RS}"  if c["WARNING"]  else f"{'0':>4}"
            info_s = f"{B}{c['INFO']:>4}{RS}"     if c["INFO"]     else f"{'0':>4}"
            print(f"  {dep:<40}  {crit_s}  {warn_s}  {info_s}")

        print(f"\n  Total: {len(issues)} issues across {len(dep_counts)} deployments\n")
        print(f"{BOLD}{'─'*72}{RS}\n")

    else:
        if "--once" in sys.argv:
            # Skip web server — port 8080 may already be held by the running agent
            run_once()
        else:
            _node_watcher.start()
            start_web_server()
            run_loop()

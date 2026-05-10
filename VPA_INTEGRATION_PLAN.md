# VPA → SRE-Agent Integration Plan

---

## 1. Integration Sequence

```
Step 1  Apply updated RBAC            → grants SRE-Agent access to VPA CRDs
Step 2  Validate VPA CRD exists       → confirm recommender has written objects
Step 3  Add VPA reader to agent.py    → poll/normalize recommendation data
Step 4  Expose /api/vpa endpoint      → structured JSON feed for dashboard
Step 5  Add VPA section to dashboard  → render current vs recommended table
Step 6  Rebuild + deploy image        → roll out updated agent
Step 7  Validate end-to-end           → confirm data flows through all layers
```

**Dependencies:**

| Step | Depends On |
|---|---|
| 1 | VPA CRD installed (teammate's task) |
| 2 | Step 1 complete |
| 3 | Step 2 validated |
| 4 | Step 3 complete |
| 5 | Step 4 complete |
| 6 | Steps 3–5 complete |
| 7 | Step 6 deployed |

**Validation checkpoints:**

- After Step 1: `kubectl auth can-i list verticalpodautoscalers --as=system:serviceaccount:sre-agent:sre-agent -A`
- After Step 2: `kubectl get vpa -A` returns objects with populated `.status.recommendation`
- After Step 6: `curl http://localhost:8080/api/vpa` returns non-empty JSON
- After Step 7: Dashboard VPA section shows container rows with target/bounds

---

## 2. VPA Integration Requirements

### Namespace Assumptions

The SRE-Agent runs in the `sre-agent` namespace and reads VPA objects **cluster-wide**. VPA objects are namespace-scoped (they live alongside the workloads they target), so cluster-wide list access is required.

Expected VPA namespaces based on current cluster layout:

| Namespace | Workload |
|---|---|
| `odoo` / tenant namespaces | Odoo web, workers, longpolling |
| `monitoring` | Prometheus, Grafana (optional) |
| Any namespace where recommender is enabled | Automatic |

The agent skips namespaces in its `SKIP_NS` set (`kube-system`, `cert-manager`, `monitoring`, `ingress-nginx`, `nfs`, `kube-public`, `kube-node-lease`) when displaying recommendations unless the team explicitly includes them.

### Required RBAC

The `01-rbac.yaml` ClusterRole has been updated with:

```yaml
- apiGroups: ["autoscaling.k8s.io"]
  resources:
    - verticalpodautoscalers
  verbs: ["get", "list", "watch"]
```

Apply immediately after VPA CRDs are confirmed installed:

```bash
kubectl apply -f k8s/01-rbac.yaml
```

Verify permission:

```bash
kubectl auth can-i list verticalpodautoscalers \
  --as=system:serviceaccount:sre-agent:sre-agent \
  --all-namespaces
# Expected: yes
```

### API Resources Used

| Field | Value |
|---|---|
| API Group | `autoscaling.k8s.io` |
| Version | `v1` |
| Resource | `verticalpodautoscalers` |
| Scope | Namespaced (read cluster-wide) |
| Client method | `CustomObjectsApi.list_cluster_custom_object()` |

Key fields consumed from each VPA object:

```
metadata.namespace
metadata.name
spec.targetRef.kind         → "Deployment", "StatefulSet", etc.
spec.targetRef.name         → workload name
spec.updatePolicy.updateMode → "Off" | "Initial" | "Auto"
status.recommendation.containerRecommendations[].containerName
status.recommendation.containerRecommendations[].target.cpu
status.recommendation.containerRecommendations[].target.memory
status.recommendation.containerRecommendations[].lowerBound.cpu
status.recommendation.containerRecommendations[].lowerBound.memory
status.recommendation.containerRecommendations[].upperBound.cpu
status.recommendation.containerRecommendations[].upperBound.memory
status.recommendation.containerRecommendations[].uncappedTarget.cpu
status.recommendation.containerRecommendations[].uncappedTarget.memory
status.conditions[].type    → "RecommendationProvided" | "NoPodsMatched"
status.conditions[].status  → "True" | "False"
```

### Operational Considerations

**Recommendation readiness:** A VPA object may exist before the recommender has observed enough data. `status.recommendation` will be absent or empty for new VPAs. The agent must handle this gracefully and display a "Collecting data" state rather than an error.

**Update mode:** If `spec.updatePolicy.updateMode` is `Auto` or `Initial`, the VPA admission controller will mutate pod specs. In this case the "current" values the agent reads from pod specs may already reflect VPA adjustments, making the delta smaller than expected. The dashboard should display the VPA mode alongside recommendations.

**Polling lag:** The VPA recommender typically recalculates every 1–24 hours depending on workload stability. A 5-minute agent poll is sufficient — recommendations are not real-time.

**Missing status:** VPAs with `NoPodsMatched` condition (target workload scaled to zero or selector mismatch) will have no recommendation. The agent surfaces this as a warning.

---

## 3. SRE-Agent Configuration

### VPA Reader Function (add to `agent.py`)

Add this function after the existing `_pod_restart_snapshot()` function:

```python
# ── VPA Cache ────────────────────────────────────────────────────────
_VPA_CACHE: List[Dict] = []
_VPA_CACHE_TS: float = 0.0
_VPA_CACHE_TTL: int = 300  # 5 minutes — VPA recommender updates slowly

def _read_vpa_recommendations() -> List[Dict]:
    """Read VPA recommendations cluster-wide via the CustomObjects API.

    Returns a normalized list of per-container recommendation records.
    Handles missing status gracefully (VPA exists but recommender hasn't
    produced data yet).
    """
    global _VPA_CACHE, _VPA_CACHE_TS
    now = time.time()
    if _VPA_CACHE and (now - _VPA_CACHE_TS) < _VPA_CACHE_TTL:
        return _VPA_CACHE

    results: List[Dict] = []
    try:
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()

        custom_api = client.CustomObjectsApi()
        vpa_list = custom_api.list_cluster_custom_object(
            group="autoscaling.k8s.io",
            version="v1",
            plural="verticalpodautoscalers",
        )

        for vpa in vpa_list.get("items", []):
            meta       = vpa.get("metadata", {})
            spec       = vpa.get("spec", {})
            status     = vpa.get("status", {})
            ns         = meta.get("namespace", "")
            vpa_name   = meta.get("name", "")
            target_ref = spec.get("targetRef", {})
            update_mode = spec.get("updatePolicy", {}).get("updateMode", "Off")

            # Check recommender condition
            conditions = status.get("conditions", [])
            rec_provided = any(
                c.get("type") == "RecommendationProvided" and c.get("status") == "True"
                for c in conditions
            )
            no_pods = any(
                c.get("type") == "NoPodsMatched" and c.get("status") == "True"
                for c in conditions
            )

            container_recs = status.get("recommendation", {}).get(
                "containerRecommendations", []
            )

            if not container_recs:
                # VPA exists but no recommendation yet — still surface it
                results.append({
                    "ns":            ns,
                    "vpa_name":      vpa_name,
                    "target_kind":   target_ref.get("kind", "Deployment"),
                    "target_name":   target_ref.get("name", ""),
                    "update_mode":   update_mode,
                    "container":     "",
                    "ready":         False,
                    "no_pods":       no_pods,
                    "target_cpu":    "",  "target_mem":    "",
                    "lower_cpu":     "",  "lower_mem":     "",
                    "upper_cpu":     "",  "upper_mem":     "",
                    "uncapped_cpu":  "",  "uncapped_mem":  "",
                })
                continue

            for cr in container_recs:
                target  = cr.get("target", {})
                lower   = cr.get("lowerBound", {})
                upper   = cr.get("upperBound", {})
                uncap   = cr.get("uncappedTarget", {})
                results.append({
                    "ns":           ns,
                    "vpa_name":     vpa_name,
                    "target_kind":  target_ref.get("kind", "Deployment"),
                    "target_name":  target_ref.get("name", ""),
                    "update_mode":  update_mode,
                    "container":    cr.get("containerName", ""),
                    "ready":        rec_provided,
                    "no_pods":      no_pods,
                    # Recommended target (what VPA wants to set)
                    "target_cpu":   target.get("cpu",    ""),
                    "target_mem":   target.get("memory", ""),
                    # Safety bounds
                    "lower_cpu":    lower.get("cpu",    ""),
                    "lower_mem":    lower.get("memory", ""),
                    "upper_cpu":    upper.get("cpu",    ""),
                    "upper_mem":    upper.get("memory", ""),
                    # Uncapped: what VPA would recommend without LimitRange caps
                    "uncapped_cpu": uncap.get("cpu",    ""),
                    "uncapped_mem": uncap.get("memory", ""),
                })

    except client.ApiException as e:
        if e.status == 404:
            logging.warning("VPA CRD not installed (404) — skipping VPA check")
        elif e.status == 403:
            logging.warning("VPA RBAC denied (403) — add autoscaling.k8s.io to ClusterRole")
        else:
            logging.warning("VPA API error: %s", e)
    except Exception as e:
        logging.warning("VPA read error: %s", e)

    _VPA_CACHE    = results
    _VPA_CACHE_TS = time.time()
    return results
```

### API Endpoint (add to HTTP handler)

Add `/api/vpa` to the existing `do_GET` handler in the `SREAgentHTTPHandler` class:

```python
elif path == "/api/vpa":
    data = json.dumps(_read_vpa_recommendations(), default=str).encode()
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(data)))
    self.end_headers()
    self.wfile.write(data)
```

### Polling Strategy

| Parameter | Value | Rationale |
|---|---|---|
| Method | Poll (not Watch) | VPA recommendations update every 1–24h; watch adds complexity with no benefit |
| Interval | 300s (matches `CHECK_INTERVAL`) | Agent already runs on this cadence |
| Cache TTL | 300s | Avoids redundant API calls between dashboard refreshes |
| Degradation | Empty list + log warning | No crash if VPA CRD absent |

### Data Normalization

VPA returns resource strings in Kubernetes format (`"100m"`, `"256Mi"`). No transformation is applied — the agent passes them through as strings. The dashboard JavaScript parses them for comparison and delta calculation using the same `_cpu()` / `_mem()` helpers already used in the cost attribution section.

---

## 4. Dashboard Specification

### VPA Section HTML (add to `_WEB_UI` template)

Add after the existing Cost Attribution section:

```html
<!-- ── VPA Recommendations ──────────────────────────────────────── -->
<section>
  <h2>&#9651; VPA Recommendations <span class="cnt" id="vpa-cnt"></span></h2>
  <div id="vpa-unavail" class="res-unavail" style="display:none">
    &#9888;&#65039; VPA CRD not found — install the VPA recommender to enable.
  </div>
  <div id="vpa-table"></div>
</section>
```

### Dashboard JavaScript

```javascript
/* ── VPA Recommendations ──────────────────────────────────────── */
function fetchVpa(){
  fetch('/api/vpa')
    .then(function(r){return r.json();})
    .then(renderVpa)
    .catch(function(){});
}

function parseCpuM(s){
  if(!s)return 0;
  if(s.endsWith('m'))return parseFloat(s);
  return parseFloat(s)*1000;  /* whole cores → millicores */
}
function parseMemMi(s){
  if(!s)return 0;
  if(s.endsWith('Ki'))return parseFloat(s)/1024;
  if(s.endsWith('Mi'))return parseFloat(s);
  if(s.endsWith('Gi'))return parseFloat(s)*1024;
  return parseFloat(s)/1048576;  /* bytes */
}
function fmtDelta(current,recommended,parseFn){
  if(!current||!recommended)return '<span class="mu">—</span>';
  var cur=parseFn(current), rec=parseFn(recommended);
  if(cur===0)return '<span class="mu">—</span>';
  var pct=Math.round((rec-cur)/cur*100);
  if(Math.abs(pct)<5)return '<span style="color:var(--grn)">≈ match</span>';
  var arrow=pct>0?'▲':'▼';
  var col=pct>50||pct<-30?'var(--red)':pct>20||pct<-15?'var(--yel)':'var(--grn)';
  return '<span style="color:'+col+'">'+arrow+' '+Math.abs(pct)+'%</span>';
}

function renderVpa(data){
  var el=document.getElementById('vpa-table');
  var cnt=document.getElementById('vpa-cnt');
  var unavEl=document.getElementById('vpa-unavail');
  if(!el)return;

  /* No VPA CRD installed at all */
  if(!data||data.length===0){
    if(unavEl)unavEl.style.display='';
    el.innerHTML='';
    if(cnt)cnt.textContent='';
    return;
  }
  if(unavEl)unavEl.style.display='none';

  /* filter: only show rows that have recommendations (ready=true) */
  var ready=data.filter(function(r){return r.ready;});
  var pending=data.filter(function(r){return !r.ready;});
  if(cnt)cnt.textContent='('+ready.length+' ready, '+pending.length+' pending)';

  /* apply global namespace filter */
  var filtered=ready;
  if(st.gf){
    filtered=ready.filter(function(r){
      return r.ns.toLowerCase().indexOf(st.gf.toLowerCase())>=0;
    });
  }

  if(!filtered.length&&!pending.length){
    el.innerHTML='<p class="empty">No VPA recommendations available yet. '+
      'The recommender needs to observe workloads before producing data.</p>';
    return;
  }

  /* build rows */
  var rows=filtered.map(function(r){
    var modeColor=r.update_mode==='Auto'?'var(--grn)':
                  r.update_mode==='Initial'?'var(--yel)':'var(--mu)';

    /* CPU delta: current request (from agent cost data if available) vs VPA target */
    /* We show VPA target and bounds — current requests come from cost attribution */
    return '<tr>'+
      '<td><span style="background:#1c2128;border-radius:3px;padding:1px 6px;font-size:11px">'+
        esc(r.ns)+'</span></td>'+
      '<td class="mono mu" style="font-size:11px">'+esc(r.target_kind)+'/'+esc(r.target_name)+'</td>'+
      '<td class="mono mu">'+esc(r.container)+'</td>'+
      '<td style="color:'+modeColor+';font-size:10px">'+esc(r.update_mode)+'</td>'+
      /* CPU columns */
      '<td class="mono" style="color:var(--blu)">'+esc(r.target_cpu||'—')+'</td>'+
      '<td class="mono mu" style="font-size:10px">'+
        esc(r.lower_cpu||'—')+' – '+esc(r.upper_cpu||'—')+'</td>'+
      '<td class="mono" style="color:var(--mu);font-size:10px">'+esc(r.uncapped_cpu||'—')+'</td>'+
      /* Memory columns */
      '<td class="mono" style="color:var(--pur)">'+esc(r.target_mem||'—')+'</td>'+
      '<td class="mono mu" style="font-size:10px">'+
        esc(r.lower_mem||'—')+' – '+esc(r.upper_mem||'—')+'</td>'+
      '<td class="mono" style="color:var(--mu);font-size:10px">'+esc(r.uncapped_mem||'—')+'</td>'+
      '</tr>';
  }).join('');

  /* pending VPAs (no recommendation yet) */
  var pendingRows=pending.map(function(r){
    var reason=r.no_pods
      ?'<span style="color:var(--red);font-size:10px">No pods matched</span>'
      :'<span style="color:var(--mu);font-size:10px">Collecting data…</span>';
    return '<tr style="opacity:.6">'+
      '<td><span style="background:#1c2128;border-radius:3px;padding:1px 6px;font-size:11px">'+
        esc(r.ns)+'</span></td>'+
      '<td class="mono mu" colspan="2" style="font-size:11px">'+
        esc(r.target_kind)+'/'+esc(r.target_name)+'</td>'+
      '<td colspan="7">'+reason+'</td>'+
      '</tr>';
  }).join('');

  el.innerHTML='<table><thead><tr>'+
    '<th>Namespace</th><th>Target</th><th>Container</th><th>Mode</th>'+
    '<th>CPU Target</th><th>CPU Range (lo–hi)</th><th>CPU Uncapped</th>'+
    '<th>Mem Target</th><th>Mem Range (lo–hi)</th><th>Mem Uncapped</th>'+
    '</tr></thead><tbody>'+rows+pendingRows+'</tbody></table>';
}
```

### Wiring into `fetchAll()`

Add to the existing `fetchAll()` function:

```javascript
function fetchAll(){
  // ... existing fetches ...
  fetchVpa();   // ← add this line
}
```

And schedule periodic refresh alongside the existing timer:

```javascript
// In the setInterval block (RSEC = 60s in current agent)
setInterval(function(){
  // ... existing refresh calls ...
  fetchVpa();
}, RSEC * 1000);
```

### Key Display Fields

| Column | Source Field | Notes |
|---|---|---|
| Namespace | `metadata.namespace` | Filterable via global NS filter |
| Target | `spec.targetRef.kind/name` | e.g. `Deployment/odoo-web` |
| Container | `containerRecommendations[].containerName` | One row per container |
| Mode | `spec.updatePolicy.updateMode` | Off/Initial/Auto — color coded |
| CPU Target | `target.cpu` | What VPA recommends setting as request |
| CPU Range | `lowerBound.cpu – upperBound.cpu` | Safety envelope |
| CPU Uncapped | `uncappedTarget.cpu` | Without LimitRange constraints |
| Mem Target | `target.memory` | Recommended memory request |
| Mem Range | `lowerBound.memory – upperBound.memory` | Safety envelope |
| Mem Uncapped | `uncappedTarget.memory` | Without LimitRange constraints |

### Refresh Interval

- **Dashboard poll:** every 60 seconds (matches existing agent refresh cadence)
- **Agent cache TTL:** 300 seconds (VPA recommender updates slowly; no benefit polling faster)
- **Effective data age:** maximum 5 minutes, typically 60 seconds

---

## 5. Validation Commands

### Step 1 — VPA CRD and objects exist

```bash
# Confirm CRD is installed
kubectl get crd verticalpodautoscalers.autoscaling.k8s.io

# List all VPA objects cluster-wide
kubectl get vpa -A

# Check a specific VPA has recommendations
kubectl get vpa -n <namespace> <vpa-name> -o jsonpath=\
  '{.status.recommendation.containerRecommendations}' | python3 -m json.tool
```

### Step 2 — RBAC is correct

```bash
# Test as the SRE-Agent service account
kubectl auth can-i list verticalpodautoscalers \
  --as=system:serviceaccount:sre-agent:sre-agent \
  --all-namespaces
# Expected: yes

# If not yet deployed, test after applying RBAC:
kubectl apply -f k8s/01-rbac.yaml
```

### Step 3 — SRE-Agent reads VPA data

```bash
# Port-forward to the running agent
kubectl port-forward -n sre-agent svc/sre-agent 8080:80

# In a second terminal — check the VPA endpoint
curl -s http://localhost:8080/api/vpa | python3 -m json.tool

# Expected: array of recommendation objects with target_cpu, target_mem populated
# Empty array means VPA CRD not found or RBAC denied (check agent logs)

# Check agent logs for VPA-related messages
kubectl logs -n sre-agent deploy/sre-agent | grep -i vpa
```

### Step 4 — Dashboard shows fresh data

```bash
# Open the dashboard
kubectl port-forward -n sre-agent svc/sre-agent 8080:80
# Open: http://localhost:8080/
# Scroll to "VPA Recommendations" section
# Verify the cnt badge shows "(N ready, M pending)"
# Verify target CPU/memory values match kubectl get vpa output
```

### Step 5 — End-to-end data freshness check

```bash
# Trigger a manual VPA recommendation check by clearing the cache:
# (exec into pod and touch the process — cache expires in 5 min naturally)
kubectl exec -n sre-agent deploy/sre-agent -- python agent.py --once 2>&1 | grep -i vpa

# Confirm timestamp of last API poll in logs:
kubectl logs -n sre-agent deploy/sre-agent --tail=50 | grep -i "vpa"
```

---

## 6. Troubleshooting

### RBAC Failures

**Symptom:** `VPA RBAC denied (403)` in agent logs, empty `/api/vpa` response.

```bash
# Confirm the ClusterRole has the VPA rule
kubectl get clusterrole sre-agent-reader -o yaml | grep -A5 autoscaling.k8s.io

# If missing, reapply RBAC
kubectl apply -f k8s/01-rbac.yaml

# Verify again
kubectl auth can-i list verticalpodautoscalers \
  --as=system:serviceaccount:sre-agent:sre-agent -A
```

**Root cause:** RBAC applied before the teammate installed the VPA CRD. Apply order doesn't matter — RBAC rules referencing non-existent API groups are silently accepted by Kubernetes but won't take effect until the CRD exists. Re-apply RBAC after CRD is installed.

---

### Missing Recommendations

**Symptom:** VPA objects exist but `status.recommendation` is absent. Dashboard shows "Collecting data…"

```bash
# Check VPA conditions
kubectl get vpa -n <ns> <name> -o jsonpath='{.status.conditions}' | python3 -m json.tool

# Common conditions and meanings:
# RecommendationProvided=False  → recommender hasn't had enough samples yet (wait 1h+)
# NoPodsMatched=True            → targetRef selector finds no running pods
# LowConfidence=True            → too few samples for reliable recommendation
```

**Resolution:** Wait for the recommender to observe sufficient pod metrics. New workloads typically need 30 minutes to several hours before the first recommendation appears. Ensure the target workload has running pods and that `spec.targetRef` matches the correct name and kind.

---

### Stale Dashboard Data

**Symptom:** Dashboard shows old recommendations after a VPA object was updated.

```bash
# Check the agent's cache age — it expires every 300s automatically
# Force refresh by restarting the agent pod (zero-downtime — one replica):
kubectl rollout restart deployment/sre-agent -n sre-agent

# Or wait for the 5-minute cache TTL to expire naturally
```

If staleness is systematic, reduce `_VPA_CACHE_TTL` in agent.py from 300 to 60 seconds — acceptable since VPA API calls are lightweight read operations.

---

### Sync Delays

**Symptom:** VPA recommender has updated a recommendation but `/api/vpa` still returns the old value.

The maximum observable delay is:

```
Agent cache TTL (300s) + Dashboard poll interval (60s) = up to 6 minutes
```

This is expected and acceptable for VPA data which changes every 1–24 hours. If near-real-time VPA data is required, switch to a **watch** strategy using `kubernetes.watch.Watch()` on the VPA custom resource, which would push updates within seconds but requires a persistent connection in the agent's background thread.

---

### API Parsing Issues

**Symptom:** `/api/vpa` returns data but fields like `target_cpu` are empty strings.

```bash
# Inspect raw VPA object structure from the cluster
kubectl get vpa -n <ns> <name> -o json | python3 -m json.tool | grep -A30 '"recommendation"'
```

Common causes:

- **VPA version mismatch:** Some clusters use `autoscaling.k8s.io/v1beta2` (older VPA). The agent uses `v1`. Check with:
  ```bash
  kubectl api-resources | grep verticalpodautoscaler
  ```
  If version is `v1beta2`, update the `version` parameter in `list_cluster_custom_object()` call.

- **Recommender not running:** The Admission Controller and Updater may be installed without the Recommender. Without the Recommender component, `status.recommendation` will always be empty.
  ```bash
  kubectl get pods -n kube-system | grep vpa
  # Should show: vpa-recommender, vpa-updater, vpa-admission-controller
  ```

- **`updateMode: Off` with no history:** In `Off` mode, VPA still generates recommendations (it just doesn't apply them). If recommendations are still absent, the recommender hasn't processed the workload yet.

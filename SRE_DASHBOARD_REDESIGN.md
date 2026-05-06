# SRE Agent Dashboard Redesign
## Operational Visibility Without Scrolling

---

## 1. Audit — What Currently Exists

| Component | What It Shows | Gap |
|---|---|---|
| Pod Restart Activity (line chart) | Restart counts per namespace, 1d/7d/30d toggle | No deployment event markers, no correlation layer |
| CPU + Memory charts (side-by-side) | Namespace-level saturation over time with hover tooltips | No p50/p95/p99 latency, no error rate |
| Namespace Cost Attribution (table) | Monthly cost per namespace, driver badge, OCI commitment rows | Efficiency score exists but buried in table |
| Issues Feed | Active problems with severity badges | No incident count summary, no toil score |
| Node Events | Warning-type K8s events | Flat list, no timeline overlay |
| Global Namespace Filter | Unified filter across all sections | Applied reactively, not part of the primary layout |
| Health endpoint `/health` | JSON liveness check | Not surfaced in UI |
| API endpoints | `/api/status`, `/api/history`, `/api/node-events` | Data exists but dashboard doesn't use history for heatmap |

**What the agent already collects that the UI doesn't use well:**
- `MetricsCollector._ns_snaps` — 30 days of CPU/mem snapshots at 60s resolution (perfect for a heatmap)
- ReplicaSet creation timestamps — deployment events are already fetched, not overlaid on charts
- Issue history — issues accumulate per check cycle but no weekly toil count is calculated
- OOMKilled + CrashLoopBackOff events with timestamps — error budget burn rate is derivable

---

## 2. Above-the-Fold Layout

Target viewport: **1440 × 900** (standard team lead laptop, browser chrome = ~80px). Usable area: **1440 × 820px**.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ HEADER BAR                                                        [60px]   │
│  🟢 proptech-prod  │  4 nodes  │  Last check: 14s ago  │  🔴 3 critical   │
│  Namespace: [All ▾]            Timerange: [1h ▾]        [Refresh ↺]       │
├────────────────────────────────────────────────────────────────────────────┤
│ ROW 1 — GOLDEN SIGNALS STRIP                                      [180px]  │
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ SATURATION   │  │ ERROR RATE   │  │ RESTARTS     │  │ COST EFF.    │  │
│  │              │  │              │  │              │  │              │  │
│  │ cpu  ███ 71% │  │  odoo  2.1%  │  │  24h:  12    │  │ odoo  🟡 41% │  │
│  │ mem  ████88% │  │  awqaf 0.3%  │  │   7d:  44    │  │ awqaf 🔴 18% │  │
│  │              │  │  proptech 0% │  │  30d: 103    │  │ odoo-w🟢 76% │  │
│  │ [sparkline]  │  │ [bar chart]  │  │ [mini chart] │  │ [score list] │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
├────────────────────────────────────────────────────────────────────────────┤
│ ROW 2 — OPERATIONAL PULSE                                         [100px]  │
│                                                                            │
│  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────────────┐│
│  │ ACTIVE INCIDENTS   │  │ WEEKLY TOIL        │  │ LAST DEPLOYMENT       ││
│  │                    │  │                    │  │                       ││
│  │  🔴 3  critical    │  │  ⚙️ 14 ops this wk │  │  odoo  →  v16.3.1    ││
│  │  🟡 7  warnings    │  │  ▲ +4 vs last wk   │  │  14:32 · 23 min ago  ││
│  │  ℹ️ 12  info       │  │  [7-day sparkline] │  │  🟢 healthy          ││
│  └────────────────────┘  └────────────────────┘  └───────────────────────┘│
├────────────────────────────────────────────────────────────────────────────┤
│ ROW 3 — SATURATION HEATMAP  (left 60%)  +  DEPLOYMENT TIMELINE (right 40%)│
│                                                                   [280px]  │
│  ┌───────────────────────────────────────┐  ┌─────────────────────────┐   │
│  │ NAMESPACE × TIME HEATMAP             │  │ DEPLOYMENT IMPACT       │   │
│  │                                       │  │                         │   │
│  │       00  02  04  06  08  10  12  14  │  │ restarts                │   │
│  │ odoo  🟢  🟢  🟡  🔴  🔴  🟡  🟢  🟢  │  │  ▁▂▁▁▁▁▅▅▅▁▁▁▂▁▁▁▁    │   │
│  │ awqaf 🟢  🟢  🟢  🟢  🟡  🟡  🟢  🟢  │  │         ↑              │   │
│  │ odoo-w🟡  🟡  🔴  🔴  🔴  🟡  🟢  🟢  │  │       deploy           │   │
│  │ prop  🟢  🟢  🟢  🟢  🟢  🟢  🟡  🟡  │  │  v16.3.1 @ 11:47      │   │
│  │ sre-a 🟢  🟢  🟢  🟢  🟢  🟢  🟢  🟢  │  │                         │   │
│  │                                       │  │ [toggle: restarts/cpu]  │   │
│  │  🟢<50%  🟡50-80%  🔴>80%  [CPU|MEM] │  │                         │   │
│  └───────────────────────────────────────┘  └─────────────────────────┘   │
├────────────────────────────────────────────────────────────────────────────┤
│ ROW 4 — ISSUES FEED (scrollable panel, above-fold shows top 5)    [200px]  │
│                                                                            │
│  🔴  odoo         OOMKilled  ×3 in 2h     worker-7f4bc  →  Add mem limit  │
│  🔴  odoo-workers CrashLoop  ×8           longpoll-pod  →  Check entrypt  │
│  🟡  awqaf        PVC Pending 34 min      data-pvc-0   →  Check storage   │
│  🟡  odoo         RS stale   14 days old  odoo-rs-old  →  kubectl delete  │
│  ℹ️  proptech      No limits  deployment  app-deploy   →  Set resources   │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

**Pixel budget breakdown (820px total):**
- Header bar: 60px
- Row 1 (Golden Signals): 180px
- Row 2 (Operational Pulse): 100px
- Row 3 (Heatmap + Timeline): 280px
- Row 4 (Issues Feed): 200px
- **Total: 820px ✓**

Everything critical is visible. Scrolling down reveals: full issue list, cost attribution table, node events detail, security findings, and the existing CPU/memory time-series charts.

---

## 3. Top 4 Enhancements — Ranked by Impact + Feasibility

### #1 — Saturation Heatmap
**Why it matters to a team lead:**
The current side-by-side line charts require reading 6–8 overlapping lines per chart to understand which namespaces are under pressure. The heatmap collapses that cognitive load to a single glance. A team lead sees immediately: odoo-workers was red from 02:00–09:00 — that's a nightly batch job causing memory pressure. No chart reading required.

**Decision it surfaces:** "Which namespace do I investigate first, and has the pressure been constant or intermittent?"

**Data already in the agent:**
- `MetricsCollector._ns_snaps` stores `{ts, cpu:{ns→m}, mem:{ns→mi}}` at 60-second resolution for 30 days. Everything needed is already collected.
- `_pod_restart_snapshot()` already computes `cpu_eff` and `mem_eff` per namespace.

**New data needed:** None. The heatmap is a pure rendering change over existing data.

**Implementation complexity:** Low. Replace the current two line charts with one SVG grid. Each cell is a `<rect>` colored by the average saturation within that hourly bucket. The existing `renderMetrics()` function already iterates over the snapshot data — add a `renderHeatmap()` function that buckets the same data differently.

```javascript
// Pseudocode — each cell color from existing _ns_snaps data
buckets[ns][hour] = avg(snaps.filter(s => hour(s.ts) === hour).map(s => s.cpu[ns] / requested[ns]))
color = bucket > 0.8 ? RED : bucket > 0.5 ? AMBER : GREEN
```

---

### #2 — Deployment Impact Timeline Overlay
**Why it matters to a team lead:**
The most common question after any incident is "did this start after a deployment?" Currently, the team lead has to cross-reference restart charts with deployment timestamps manually. Overlaying a vertical marker at every ReplicaSet creation event answers the question in under 2 seconds.

**Decision it surfaces:** "Is this spike caused by the 11:47 deploy, or was it already happening? Do I rollback?"

**Data already in the agent:**
- The agent already fetches `AppsV1Api.list_replica_set_for_all_namespaces()` in `_pod_restart_snapshot()`. ReplicaSet creation timestamps (`rs.metadata.creation_timestamp`) are already being iterated to find stale RSes — the deploy events are right there.
- The restart history is already rendered as an SVG line chart with a known time axis.

**New data needed:** None for K8s deployments. For application-level deploys (e.g., image tag changes), compare `rs.spec.template.spec.containers[0].image` across RS generations.

**Implementation complexity:** Low-Medium. Parse RS creation timestamps into a sorted array. In `drawChart()`, after drawing all lines, add a second pass that renders vertical `<line>` elements at the corresponding x-position for each deploy event, with a small label showing the image tag. The tooltip on hover shows: namespace, image tag, time, and whether restarts increased within the next 30 minutes.

---

### #3 — Cost Efficiency Score (Red/Amber/Green per Namespace)
**Why it matters to a team lead:**
The current cost table shows dollar amounts but not whether the spend is justified. A namespace costing $400/month with 12% CPU efficiency is a clear action item. A namespace at $400/month with 85% efficiency is fine. The score turns a financial number into an operational decision.

**Decision it surfaces:** "Which namespaces are burning money on unused reservations? Where should I reduce resource requests to lower costs?"

**Data already in the agent:**
- `_pod_restart_snapshot()` already computes `cpu_eff = actual_cpu_m / requested_cpu_m` and `mem_eff = actual_mem_mi / requested_mem_mi` per namespace.
- Cost per namespace is already calculated.
- Both values exist in the same data structure — the score is a one-line derivation.

**New data needed:** None.

**Implementation complexity:** Low. Add an `eff_score` to each namespace in `by_ns`: average of `cpu_eff` and `mem_eff`, capped at 100%. In `renderCost()`, prepend a colored dot before the namespace name. Add the efficiency score as a column. In the new Golden Signals row, render it as a sorted list of namespace badges.

```python
eff_score = round((cpu_eff + mem_eff) / 2 * 100, 1)
color = "green" if eff_score >= 60 else "amber" if eff_score >= 30 else "red"
```

---

### #4 — Weekly Toil Tracker
**Why it matters to a team lead:**
Toil is the canary metric for platform health. If toil is rising week over week, something is fundamentally broken — a flapping deployment, a memory leak, a cron job that always fails. It's the leading indicator before incidents become visible. No other dashboard panel captures this.

**Decision it surfaces:** "Is the platform getting more stable or less stable over time? Where is the manual work coming from?"

**Toil events already logged by the agent:**
- OOMKill events (pod required manual attention or restart)
- CrashLoopBackOff counts (each restart cycle = one toil unit)
- PVC Pending events (required storage intervention)
- Failed Jobs (required manual re-trigger)
- Pod evictions (required rescheduling attention)

**New data needed:** A running weekly counter. Add a `_toil_log` deque to `MetricsCollector` that appends `{ts, ns, type}` for each detected toil event. The weekly sum is a filter over the last 7 days.

**Implementation complexity:** Medium. Requires instrumenting 4–5 check functions to emit toil events into the collector. The UI rendering is simple — a number badge with a 7-day sparkline and a delta vs. last week. The harder part is defining what counts as toil consistently (avoid double-counting a CrashLoop that fires 20 times in an hour as 20 toil events — cap per pod per hour).

---

## 4. Drill-Down Interactions

When a team lead clicks any element in the above-fold view, the panel expands in-place (no page navigation) to show deeper context:

**Click on a heatmap cell** → Expands to show the CPU/memory time-series line chart for that namespace during that hour, plus any events that fired in the same window. Answers: "What exactly happened at 03:00 in odoo-workers?"

**Click on a deployment marker** → Shows a side-by-side diff: restarts in the 30 minutes before vs. after the deploy, the image tag that changed, and a one-click rollback command (`kubectl rollout undo deploy/<name> -n <ns>`).

**Click on an efficiency score badge** → Shows the top 5 over-provisioned pods in that namespace ranked by waste (requested - actual), with the exact `resources.requests` values and what they should be changed to.

**Click on Active Incidents count** → Expands the issues feed inline, pre-filtered to critical severity only.

**Click on Weekly Toil number** → Shows the 7-day breakdown: toil per day, top contributing namespace, and top toil type (OOMKill vs CrashLoop vs Job failure).

---

## 5. What to Move Below the Fold

These panels have value but are not "first 10 seconds" material. Move them to a scrollable second section:

**Full Cost Attribution Table** — Useful for monthly planning, not daily operations. Keep the efficiency score badges above the fold; the detailed table goes below.

**Node Events List** — Node-level events are important but rare. A node count badge in the header ("4 nodes 🟢") is sufficient above the fold. The full event list scrolls.

**Security Findings** — Important but not operationally urgent on every page load. Move to a dedicated tab or below-fold section. A single "🔐 3 security findings" badge in the header is enough.

**Full CPU/Memory Line Charts** — The heatmap replaces them above the fold. Keep the detailed line charts below for when a team lead wants to investigate a specific namespace's time-series in detail.

**Odoo-Specific Reports** — Move to a dedicated tab ("Odoo") that team leads can navigate to when specifically troubleshooting Odoo. Not relevant for general platform health view.

---

## 6. Implementation Order

| Phase | What | Complexity | Impact |
|---|---|---|---|
| 1 | Cost Efficiency Score column + RAG badges in Golden Signals row | Low | High |
| 2 | Saturation Heatmap replacing the two line charts | Low | High |
| 3 | Deployment Timeline overlay on restart chart | Low-Medium | High |
| 4 | Operational Pulse row (incident count + toil tracker) | Medium | High |
| 5 | Drill-down expand-in-place interactions | Medium | Medium |
| 6 | Header bar redesign with cluster health summary | Low | Medium |

Phases 1–3 require no new data collection — they're rendering changes over data already being collected. Phase 4 requires adding the toil event counter to `MetricsCollector`. Phases 5–6 are UI polish.

Total estimated effort for phases 1–4: roughly equivalent to the work done for the unified namespace filter + side-by-side charts combined.

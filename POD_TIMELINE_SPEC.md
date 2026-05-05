# Pod Count Timeline — Technical Specification

## 1. Overview

A time-series area/line chart showing the number of **active (Running + Pending) pods
per namespace** over time, embedded in the SRE-Agent web dashboard immediately above
the Issues section.

---

## 2. Data Schema

### Snapshot record (written every poll cycle)
```json
{
  "ts":   "2026-05-05T10:30:00",
  "pods": {
    "default":       3,
    "ingress-nginx": 2,
    "kube-system":   8,
    "pro01-prod":   12,
    "sre-agent":     1
  }
}
```

### Three time-resolution stores in MetricsCollector
| Store             | Resolution | Max window | Max entries | Purpose        |
|-------------------|-----------|------------|-------------|----------------|
| `_ns_snaps`       | 60 s      | 24 h       | 300         | 1-day view     |
| `_pod_snaps_10m`  | 10 min    | 7 d        | 1 010       | 1-week view    |
| `_pod_snaps_1h`   | 1 h       | 30 d       | 730         | 1-month view   |

The 10-min and 1-hour stores are updated by comparing the ISO timestamp of the
latest entry against the new sample; if the gap exceeds the threshold, a new entry is
appended and old entries beyond the window are evicted from the left.

---

## 3. API

### `GET /api/pod-timeline`

**Query parameters**

| Parameter | Values              | Default | Description                                    |
|-----------|---------------------|---------|------------------------------------------------|
| `range`   | `1d` / `1w` / `1m`  | `1d`    | Time window to return                          |
| `biz`     | `0` / `1`           | `0`     | If `1`, keep only UTC hours 8–16 (business hrs)|

**Response**
```json
{
  "available": true,
  "range":     "1w",
  "biz":       false,
  "snaps": [
    {"ts": "2026-04-28T08:00:00", "pods": {"default": 3, "pro01-prod": 11}},
    {"ts": "2026-04-28T08:10:00", "pods": {"default": 3, "pro01-prod": 12}}
  ]
}
```

`available: false` means metrics-server is not installed; the frontend shows a
degraded message rather than an empty chart.

---

## 4. Frontend Implementation

### Library choice
**Pure SVG** — consistent with the existing CPU/RAM namespace charts; no CDN
dependency, works fully offline via `kubectl port-forward`.

### Chart design
- **Type**: area + line (semi-transparent fill at 13 % opacity, solid stroke at
  1.8 px) — shows shape AND lets overlapping series remain readable.
- **Namespaces**: top 9 by maximum pod count shown individually; any remaining
  namespaces are collapsed into a grey "other" aggregate line.
- **Colors**: reuses the 16-color `NS_PAL` palette already defined in the dashboard.
- **Dimensions**: `viewBox="0 0 900 240"`, responsive (`width="100%"`).

### Axis labels
| Range | X-axis format       | X-ticks |
|-------|---------------------|---------|
| 1 day | `HH:MM` UTC         | 7       |
| 1 week| `Mon DD`            | 7       |
| 1 month| `MMM DD`           | 7       |

Y-axis: integer pod counts, 4 gridlines + labels.

### Business-hours shading
When **All 24 h** view is active and range is `1d`, segments outside 08:00–17:00 UTC
are overlaid with a very faint white rectangle (`fill-opacity: 0.025`) to visually
de-emphasise off-hours without hiding the data.

### Hover tooltip
A **fixed-position `<div>`** (not SVG `<title>`) positioned near the cursor:
- Triggered by `mousemove` on a transparent `<rect>` overlay covering the chart area.
- A vertical crosshair SVG `<line>` moves with the cursor.
- Content: UTC timestamp + all namespace pod counts sorted by the palette order.
- Flips left when within 220 px of the viewport right edge.

### Controls toolbar
```
[Range] [1 Day] [1 Week] [1 Month]    [Hours] [All 24 h] [Business 08-17 UTC]
```
Buttons use the existing `.btn` / `.btn.on` CSS classes; toggling calls
`setPodOpt(key, val)` which updates `st.pr` / `st.pb` and re-fetches.

---

## 5. Data Pipeline Changes

### MetricsCollector._poll() additions
1. **Pod counting**: the existing `list_pod_for_all_namespaces()` call already
   iterates all pods for requests/limits. A `ns_pod_count: Dict[str, int]` counter
   is added in the same loop (zero extra API calls).

2. **`pods` field in `_ns_snaps`**: the 60-second snapshot now includes
   `"pods": {ns: count}` alongside the existing `"cpu"` and `"mem"` dicts.

3. **Downsampling** (`_iso_age_secs` helper): after each poll, two timestamp guards
   (`_last_10m_ts`, `_last_1h_ts`) decide whether to write a new entry to the
   lower-resolution stores. No separate thread or timer is needed.

### Eviction
All three stores use left-popleft eviction:
- `_ns_snaps`: existing 24 h ISO cutoff string comparison.
- `_pod_snaps_10m`: cutoff = `now − 7 days`.
- `_pod_snaps_1h`: cutoff = `now − 30 days`.

### Memory footprint
Worst case (30 namespaces, 32-char namespace names, int counts):

| Store           | Entries | ~Bytes/entry | ~Total  |
|----------------|---------|--------------|---------|
| `_ns_snaps`     | 300     | 1 000        | 300 KB  |
| `_pod_snaps_10m`| 1 010   | 700          | 710 KB  |
| `_pod_snaps_1h` | 730     | 700          | 510 KB  |

Total incremental cost: **~1.5 MB** — well within the existing 512 Mi container limit.

---

## 6. UI Placement

```
[ Resource Utilization ]   ← existing section
  Global CPU/RAM bars
  Per-node bars (CPU / RAM / DISK)
  CPU by Namespace chart
  Memory by Namespace chart

[ Pod Count by Namespace ] ← NEW section
  Toolbar: Range × Hours
  Area/line SVG chart
  Legend: ■ ns1 now:12  ■ ns2 now:3 …

[ Issues ]                 ← existing section
```

This placement groups all resource-consumption visualisations together before the
alert/issue tables, giving an SRE a top-to-bottom narrative: capacity → usage →
pod distribution → problems.

---

## 7. Known Limitations & Future Work

| Limitation | Mitigation |
|---|---|
| 1-week and 1-month stores are in-memory; data is lost on pod restart | Acceptable for a lightweight agent; persist to ConfigMap or an external TSDB (Prometheus/VictoriaMetrics) if retention is required |
| `list_pod_for_all_namespaces` is already called; pod count is free | If the pod list is paginated (> 500 pods), counts may be incomplete on first few polls |
| Business-hours filter is UTC-only | Add a `TZ` env var to shift the 08–17 window to local timezone |
| Max 9 namespaces individually shown | Expose a URL parameter (`?top=N`) to let the user adjust |

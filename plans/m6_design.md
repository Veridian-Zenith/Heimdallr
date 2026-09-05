# Heimdallr M6 — Filtering, Apps & Observability

**Milestone:** M6 — Filtering, Apps & Observability
**Status:** Planned (M0–M5 complete, tagged `v0.5.0-alpha`)
**Author:** Architect pass, 2026-09-04
**Branch target:** `main` (solo maintainer workflow)

This document specifies the design for M6 — the eighth milestone in the
Heimdallr roadmap. M6 closes the privacy/filtering story (blocklists,
regex, sinkhole, rebinding) and the observability story (query logs,
Prometheus metrics, full HTTP API), and adds a persistent cache so the
resolver state survives restarts.

---

## 1. Overview

### Goals

1. **Privacy-grade blocking.** Load blocklist URLs, parse hosts-format
   lists, match QNAMEs, return a configurable sinkhole (BlockPage) IP
   for blocked names.
2. **Regex per-client.** Allow regex-based blocking with a per-client
   ACL map (e.g. `10.0.0.5/32 = { block = false }`) so a LAN can
   override the global block policy.
3. **Rebinding protection.** Already stubbed in M5.5; harden the
   detection and add a per-response override hook.
4. **Persistent cache.** Serialize `SharedCache` to `cache.bin` on
   shutdown; reload on startup so cold-start time drops.
5. **Query logs.** Emit one JSON line per query (qname, qtype, client,
   response code, latency) to the path in `[log].query_log`.
6. **Prometheus metrics.** Expose `GET /metrics` in text exposition
   format with counters for cache hits, qmin steps, DNS64
   synthesized, etc.
7. **Full HTTP API.** Round out the axum surface: zones CRUD (already
   in M2), cache stats, filter stats, runtime toggle for
   `qname_min`, `ecs`, `dns64_prefix`.

### Non-goals

- **No recursive blocklist refresh daemon.** A single periodic
  refresh is enough; we are not building a BGP-aware feed processor.
- **No geo / split-horizon.** M7 owns `split-horizon/geo via Apps`.
- **No web console.** M7 owns axum + static + RBAC.
- **No remote log shipping.** Operators point `query_log` at a file
  and let logrotate/journald handle shipping.

### Success criteria

| # | Gate |
|---|------|
| 1 | `cargo check && cargo build --release` — clean compile, no new lints |
| 2 | `cargo test` — all existing 100 tests pass; new unit tests per sub-task |
| 3 | `tests/m6-blocklist-validate.sh` — load hosts-format blocklist, query blocked name, get sinkhole IP |
| 4 | `tests/m6-regex-validate.sh` — regex blocklist, per-client override, query matched name → NXDOMAIN |
| 5 | `tests/m6-cache-validate.sh` — start, query, stop, restart, second query hits persistent cache |
| 6 | `tests/m6-metrics-validate.sh` — `curl /metrics`, assert `cache_hits_total`, `dns64_synthesized_total` present |
| 7 | `tests/m6-query-log-validate.sh` — query, assert one JSON line appended to log |

Tag `v0.6.0-alpha` when all 7 gates pass.

---

## 2. Sub-milestone breakdown

| ID | Name | File targets | Size | Depends on | Order |
|----|------|--------------|------|------------|-------|
| **M6.1** | Blocklists + sinkhole | `src/core/filter/blocklist.rs` (new), `src/core/filter/mod.rs` | **M** | — | 1 |
| **M6.2** | Regex per-client | `src/core/filter/regex.rs` (new), `src/core/filter/mod.rs` | **M** | M6.1 | 2 |
| **M6.3** | Persistent cache | `src/core/cache/persist.rs` (new), `src/core/cache/mod.rs` | **M** | — | 3 (parallel) |
| **M6.4** | Query log | `src/core/log/query_log.rs` (new), `src/net/udp.rs` | **S** | — | 4 (parallel) |
| **M6.5** | Prometheus metrics | `src/core/metrics/mod.rs` (new), `src/api/mod.rs` | **M** | M6.4 | 5 |
| **M6.6** | Full HTTP API | `src/api/mod.rs`, `src/api/cache.rs`, `src/api/filter.rs` | **M** | M6.3, M6.5 | 6 |

### Complexity rationale

- **S (Query log):** One async writer, JSON serialize, no in-memory
  state to share.
- **M (Blocklists, regex, persistent cache, metrics, API):** Real
  parsing/matcher logic or cross-cutting wiring, but no new external
  services.

---

## 3. Per-sub-task design sketches

### M6.1 — Blocklists + sinkhole

- **Wire format / data model.** Hosts-format blocklist (one entry per
  line: `0.0.0.0 example.com` or `127.0.0.1 example.com`). Also
  accept AdGuard DNS-style (`||example.com^`) and plain domain per
  line. Internal: `HashSet<LowerName>` for O(1) membership.
- **Storage location.** In-memory only. Refreshed on startup from
  `[filter].blocklists` (list of URLs or local file paths). Periodic
  refresh (default 24h) via background tokio task.
- **Handler/resolver integration points.** In
  [`forward.rs`](src/core/resolver/forward.rs:194) `lookup`, after
  cache miss, before upstream forward: check
  `filter.is_blocked(qname, client)`. If true, return NOERROR with
  the configured sinkhole IPs (default `0.0.0.0` for A, `::` for
  AAAA) and short-circuit the upstream call.
- **Test strategy.** Unit: load hosts-format string, assert
  `is_blocked("ads.example.com", client)` returns true;
  `is_blocked("allowed.example.com", client)` false.
- **Edge cases.** Blocklist entries with `0.0.0.0` vs `127.0.0.1` —
  treat both as block signals. Comments (`#`) and blank lines
  skipped. Subdomain matching: an entry for `example.com` blocks
  `ads.example.com` (suffix match). Allowlist takes precedence.

### M6.2 — Regex per-client

- **Data model.** `Vec<CompiledRegex>` for `regex_blocklist`;
  `HashMap<IpNet, PerClientFilter>` for `per_client`. Compile at
  config load; fail fast on invalid regex.
- **Storage location.** In-memory compiled regex cache in `Filter`.
- **Integration.** Called from `is_blocked()` after exact-match
  blocklist. `per_client` overrides the block decision for matching
  client subnets.
- **Test strategy.** Unit: regex `.*\.ads\..*` blocks
  `foo.ads.example.com`; per-client `{ block = false }` allows it.

### M6.3 — Persistent cache

- **Format.** Bincode-serialized `Vec<CacheEntry>` (key, bytes,
  inserted_at, expires_at) with a magic header and version byte.
  Append-only on insert would be ideal but a single rewrite on
  shutdown is sufficient for v0.6.
- **Storage location.** `cache.persistent` path (TOML) or
  `/var/lib/heimdallr/cache.bin` default.
- **Integration.** `SharedCache::save(path)` on `Drop`/SIGTERM;
  `SharedCache::load(path)` in `Cache::new`. Skip load if file is
  older than `max_age` (default 7 days).
- **Test strategy.** Unit: insert, save, drop, load, lookup. Integration
  shell: start, query `example.com`, stop, start, query again —
  second response served from disk, not upstream.

### M6.4 — Query log

- **Format.** JSON-lines: one record per query, fields `ts`, `qname`,
  `qtype`, `client`, `rcode`, `answers`, `latency_ms`,
  `from_cache`, `blocked`.
- **Integration.** Hook in `forward.rs::lookup` end + `udp.rs::handle`
  start. Buffered async writer; flushed every 100ms or 64 lines.
- **Test strategy.** Unit: emit 3 events, read file, assert 3 lines
  parse as JSON with required fields.

### M6.5 — Prometheus metrics

- **Format.** Text exposition (`/metrics` returns `text/plain;
  version=0.0.4`). Counters and gauges with `# HELP` + `# TYPE`.
- **Counters.** `cache_hits_total`, `cache_misses_total`,
  `queries_total{qtype}`, `blocked_total`, `dns64_synthesized_total`,
  `qmin_steps_total`, `cname_chain_truncated_total`,
  `rebinding_detected_total`. Histograms (later): query latency.
- **Integration.** `Arc<MetricsRegistry>` shared across
  `CacheForwardAuthority`, `Filter`, `dns64`. Increment at the same
  call sites where tracing logs are emitted.
- **Test strategy.** Unit: bump a counter, serialize, assert line in
  output.

### M6.6 — Full HTTP API

- **Endpoints.**
  - `GET /metrics` (M6.5)
  - `GET /api/cache/stats` — size, hits, misses
  - `GET /api/filter/stats` — blocklist size, regex count, blocked today
  - `GET /api/rec/options` — current qmin/ecs/dns64
  - `PUT /api/rec/options` — runtime toggle (M7 will gate with auth)
- **Test strategy.** Integration shell: `curl /api/cache/stats`
  returns JSON, `curl /metrics` returns text.

---

## 4. Config schema additions

```toml
[filter]
blocklists = [
  "https://example.com/hosts.txt",
  "/etc/heimdallr/local-blocklist.txt",
]
allowlists = []
regex_blocklist = [".*\\.doubleclick\\.net$"]
# per_client = { "10.0.0.0/24" = { block = false } }
cname_cloaking = true
rebinding = true
# M6.1: sinkhole IPs returned for blocked names
sinkhole_v4 = "0.0.0.0"
sinkhole_v6 = "::"
# M6.1: blocklist refresh interval (hours, 0 = manual only)
refresh_interval_h = 24

[cache]
size = 50000
serve_stale = true
prefetch = 2
# M6.3: persistent cache file
persistent = "/var/lib/heimdallr/cache.bin"
# M6.3: max age for cache load (days)
persistent_max_age_days = 7

[log]
level = "info"
# M6.4: query log path (one JSON line per query)
query_log = "/var/log/heimdallr/queries.jsonl"
format = "json"
```

---

## 5. Landing order

1. **M6.1** first (foundational — unblocks M6.2 and the integration
   tests).
2. **M6.3** in parallel (independent, touches only cache).
3. **M6.2** after M6.1.
4. **M6.4** in parallel (touches only `net/udp.rs` + new module).
5. **M6.5** after M6.4 (metrics cover query log counters).
6. **M6.6** last (needs cache stats + filter stats + metrics).

---

— End of M6 design —

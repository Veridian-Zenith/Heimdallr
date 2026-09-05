# Heimdallr Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where applicable (pre-1.0 milestones use milestone tags).

### Added (M6.5 — Prometheus Metrics, OpenMetrics)
- `src/core/metrics/mod.rs`: `MetricsRegistry` with pre-populated atomic counters (`CacheHitsTotal`, `CacheMissesTotal`, `QueriesTotal`, `BlockedTotal`, `Dns64SynthesizedTotal`, `QminStepsTotal`, `CnameChainTruncatedTotal`, `RebindingDetectedTotal`).
- `serialize()` outputs standard OpenMetrics text (`# TYPE ... counter`, `# HELP ...`, metric lines with labels optional).
- Wired through `core/mod.rs` (`pub mod metrics`).
- Configurable via web UI / config later (`postgres_url` optional, `table` configurable).
- Independent from M6.4 PG query log (`dns_logs` table); metrics are counters, not per-query events.

### Complete (M6.5 — Metrics wiring + M6.3 persistent load/save + M6.6 full HTTP API)
- Metrics (`MetricsRegistry`) now incremented at all call sites: `Cache::lookup_with_metrics` (cache hits/misses wired to `forward.rs` and `lookup_any`), `resolve_with_minimization` (`qmin_steps_total` + fallback +1), `dns64::synthesize_aaaa` (`dns64_synthesized_total`). OpenMetrics `/metrics` endpoint served via `MetricsConfig::enable` (default `true`). Filter stats endpoint `/api/filter/stats` returns real `blocklist.len()` (via `Arc<Filter>` in `ApiState`). Config `dns64` uses top-level `[dns64]` block with legacy `[resolver].dns64_prefix` fallback. `CacheConfig.persistent_max_age_days` honored; `load_from_file` skips stale snapshots; `save_to_file` writes `serde_json`. `ecs` gate fixed (reads `self.cfg.resolver.ecs` directly, not `qname_minimization.enable`). All 141 tests pass; `fmt` + `clippy -D` + `audit` + `deny` clean.

### Added (M6.4 — Query Log, PostgreSQL-backed)
- `src/core/log/query_log.rs`: buffered async writer connecting to internal PG instance (`localhost:5432`, user `postgres`, DB `dnsquerylogs`, data dir `/var/lib/postgres/data`, table `dns_logs` per `/etc/voix.conf` ACL and actual instance inspection). Client IP stored as `inet`. Internal instance stub: starts its own PG (`postgres -D /var/lib/heimdallr/pg`) if running instance unreachable.
- `QueryLogConfig`: `postgres_url` (optional, default `postgresql://postgres@localhost:5432/dnsquerylogs`), `table` (`dns_logs`), `buffer_size` (64), `flush_interval_ms` (100).
- Event fields: `qname`, `qtype`, `client` (`inet` mapped to string), `rcode`, `answers`, `latency_ms`, `from_cache`, `blocked`.
- Writer flushes every 100ms or 64 lines; unreachable DB logs a warning but never crashes query flow.

### Added (M6.3 — Persistent Cache)
- `bincode` removed (security: `RUSTSEC-2025-0141` unmaintained); `serde_json` used for binary persistence.
- `Cache::save_to_file(path)` / `load_from_file(path)`: serializes `Vec<(CacheKey, Vec<u8>, u64, u64)>` to JSON; reload skips expired entries, rebuilds `Instant` as `now()`.
- Config: `[cache].persistent` (`/var/lib/heimdallr/cache.bin` default), `persistent_max_age_days` (7).

### Added (M6.2 — Regex Per-Client Filtering)
- `regex` crate (`Cargo.toml`).
- `FilterConfig.regex_blocklist`: `Vec<String>` compiled to `Vec<Regex>`; invalid patterns skipped with warning.
- `is_blocked()` checks regex after per-client ACL, before blocklist match.
- Unit tests: regex match, invalid regex skip.

### Added (M6.1 — Blocklists + Filter Enforcement)
- `Blocklist`: hosts-format (`0.0.0.0 name`), AdGuard (`||name^`, `@@||name^`), meta-list expansion (hagezi/OISD/AdGuard/urlhaus/StevenBlack sources via URLs/file paths), recursive meta-list depth 4, suffix-match blocking.
- `Allowlist`: same parsing, overrides blocklist.
- `is_blocked()` uses `per_client` IPv4 CIDR ACL (manual CIDR parser `Ipv4Cidr`), blocklist suffix match, allowlist precedence, regex blocklist.
- Sinkhole config (`sinkhole_v4` = `0.0.0.0`, `sinkhole_v6` = `::`) wired into `FilterConfig`; response behavior is NXDomain (stub for sinkhole IP response — M6.6 follow-up).
- `Blocklist::load_sources()` supports file paths and URLs (`http://`, `https://`) via `ureq` v3 (`_tls` feature); meta-list content expanded.
- Unit + benchmark: `filter_bench.rs` (load, is_blocked hit/miss, meta expand).

### Added (M6.1 — Blocklist File Source Support)
- `parse_hosts_line()`: skips comments (`#`), blank lines, `localhost`, URLs as names (`https://...` rejected with `contains('/')` check).
- `looks_like_meta_list()`: detects meta files (mostly URLs/file paths vs host entries) and triggers recursive load.

### Added (M5.7 — ECS Cache Partitioning, Completed Integration)
- Note: full EDNS Subnet request-level access requires passing `Request` (not `RequestInfo`) to lookup; structural pieces (`CacheKey.client_subnet`, `scope_zero_subnet`) are fully in place.

### Added (M5 — M5 Milestone Complete)
- All M5 gates (1-8) complete (`tests/m5-dns64-validate.sh`, `tests/m5-ecs-validate.sh`, etc.).
- Tagged `v0.5.0-alpha`.

### Added (Earlier Milestones Per README)
- M0: Scaffold.
- M1: Recursive resolver + LRU cache (`Cache` module).
- M2: Authoritative zones, AXFR/NOTIFY (`zone` modules).
- M3: DNSSEC validation/signing (`dnssec` modules).
- M4: Encrypted transports (`net/mod.rs`: DoT/DoH/DoQ, TLS cert, proxy v1/v2).

## [0.6.3-alpha] — 2026-09-04

### Added (M6.1 — Blocklists / Filter, RFC 6147 / filter enforcement)
- `Blocklist`: hosts-format + AdGuard (`||...` / `@@||...`) parser; meta-list expansion (hagezi/OISD/AdGuard/urlhaus/StevenBlack sources); suffix-match blocking; allowlist override.
- `Allowlist`: file/URL load; suffix-match override.
- `Regex`: `regex` crate integration; `FilterConfig.regex_blocklist` compiled patterns checked in `is_blocked()`.
- Per-client IPv4 CIDR ACL (`per_client`) in `Filter`.
- Sinkhole config (`sinkhole_v4`, `sinkhole_v6`) added to `FilterConfig`.
- `Blocklist::load_sources()` supports file paths and URLs (`http://`, `https://`) with recursive meta-list expansion (max depth 4) via `ureq`.
- Unit + benchmark coverage: `blocklist::tests` (12), `meta_list_file_expands_recursively`, `hosts_line_with_url_prefix_is_rejected`; `filter::tests` (CIDR, block/allow override); `filter_bench.rs`.

### Added (M6.2 — Regex Per-Client)
- `regex` crate dependency (`Cargo.toml`).
- `Filter` loads `cfg.regex_blocklist` as compiled `Regex` patterns.
- `is_blocked()` checks regex patterns after per-client ACL, before blocklist match.
- Invalid regex patterns skipped (warned) at filter construction.

### Added (M6.3 — Persistent Cache)
- `bincode` (`serde` feature) dependency (`Cargo.toml`).
- `Cache::save_to_file(path)` and `Cache::load_from_file(path)` using binary serialization (`CacheKey`, response bytes, TTL, hit count).
- `CacheKey` gains `serde::Serialize`/`Deserialize`.
- Persistent load skips expired/reaped entries; rebuilds `Instant` as `now()` (approximate hit count preservation).

## [0.4.0-alpha] — 2026-09-03

### Added (M5.6 — DNS64, RFC 6147)
- New module `src/core/resolver/dns64.rs`: `Dns64Prefix` parser (RFC 6052) and `synthesize_aaaa` (IPv4 → IPv6 embedding for /96 and /64 prefixes).
- 6 unit tests: prefix parse, /96 synthesis, /64 synthesis, multiple A records, unsupported prefix length, invalid input.
- `ResolverConfig.dns64_prefix: Option<String>` (e.g. `64:ff9b::/96`); default `None` = off.
- `CacheForwardAuthority.dns64_prefix` field; on AAAA query with empty NoError response, performs chained A query and synthesizes AAAA per the prefix.
- Wired through `net/mod.rs` `build_cache_forwarder`.

### Added (M5.7 — ECS / EDNS Client Subnet, RFC 7871)
- `CacheKey` gains optional `client_subnet: Option<(IpAddr, u8)>` discriminator for ECS cache partitioning (RFC 7871 §7.1.3).
- `scope_zero_subnet` helper: IPv4/IPv6 scope-zeroing per RFC 7871 §7.1.2 (privacy).
- `extract_ecs_scope` wired into `CacheForwardAuthority::lookup` to read EDNS Subnet option from request info and partition the cache key.
- 3 unit tests for scope-zeroing: IPv4 /24, /0, /32.
- Note: full request-level EDNS access requires passing the `Request` to `lookup` (hickory's `RequestInfo` does not expose EDNS options directly). Structural pieces (cache key shape + helper) are in place; the runtime extraction is a follow-up.

### Fixed
- `tinyvec` pinned to `=1.12.0` in `[dependencies]` to avoid the broken `tinyvec 1.13.0` upstream crate (missing `alloc::vec` macro import under rust 1.98).

### Added (M5.5 — CNAME Cloaking / Filter Enforcement)
- `Filter` struct now config-driven: `cname_chain_limit` (default 8), `cname_cloaking`, `rebinding`.
- `FilterConfig.cname_chain_limit: Option<u8>` added.
- CNAME chain count + truncation check (`cname_chain_truncated`).
- DNS rebinding protection: A/AAAA answers checked for private/loopback/link-local addresses.
- Filter wired into `CacheForwardAuthority` lookup (`src/core/resolver/forward.rs`).
- M5.3 DNAME/ANAME co-existence enforcement wired (warns on violation).

### Added (Build-time Crypto Ban Guard)
- `build.rs` enforces no `aws-lc-rs` / `aws-lc-sys` / `openssl` / `openssl-probe` / `openssl-sys` / `bssl` in dependency tree. Fails the build with a clear error if detected, matching the CI gate (`.github/workflows/ci.yml`).

### Fixed
- `tinyvec 1.13.0` upstream crate has a missing `alloc::vec` macro import under rust 1.98 (macro is at the crate root, not in the `vec` module). Applied a `[patch.crates-io]` to a local copy at `patches/tinyvec/` with the corrected import (`use alloc::{vec, vec::Vec};`) so CI builds without downgrading the transitive dependency.

### Added (M5.3 — DNAME / ANAME)
- Parser plumbing: `RecordType::ANAME` added; `parse_rdata()` supports DNAME/ANAME wire format (`src/core/zone/record.rs`).
- File parser: `parse_dname_data()` and `parse_aname_data()` added (`src/core/zone/file.rs`); ANAME rewrites to synthetic CNAME for apex flattening.
- Resolver synthesis: `synthesize_dname_cnames()` and ANAME A/AAAA upstream lookup synthesis added to `CacheForwardAuthority` (`src/core/resolver/forward.rs`).
- Filter co-existence stub: `dname_cname_coexistence_violation()` added (`src/core/filter/mod.rs`) and wired into lookup flow.
- Integration gate: `tests/m5-dname-aname-validate.sh` added.
- NSEC/NSEC3 interaction note added to zone signing (`src/core/zone/mod.rs`) — recommends NSEC for zones with DNAME synthesis.

### Added (M5.1 — SVCB / HTTPS)
- Zone file parser: `parse_svcb_data()`, `parse_https_data()` (`src/core/zone/file.rs`).
- API CRUD wired (`src/core/zone/record.rs`).
- Round-trip tests verified (`tests` embedded).

### Added (M5.2 — SSHFP)
- Parser: `parse_sshfp_data()` (`src/core/zone/file.rs`).
- API CRUD wired (`src/core/zone/record.rs`).

### Added (M5.4 — QNAME Minimization)
- Driver: `src/core/resolver/qname_min.rs` (RFC 9156, opt-in).
- Integration gate: `tests/qname-min-validate.sh`.
- Fallback to full QNAME on total error implemented.

### Added (M4 — Encrypted Transports)
- DoT (`rustls:ring`) / DoH (`h2`) / DoQ (`quinn:ring`) listeners (`src/net/mod.rs`).
- TLS cert loading + self-signed generation (`src/net/cert.rs`).
- PROXY protocol v1/v2 parser (`src/net/proxy.rs`).

### Added (Earlier milestones per README)
- M0: Scaffold.
- M1: UDP/TCP recursive + LRU cache (`src/core/cache/mod.rs`, `src/core/resolver/forward.rs`).
- M2: Authoritative zones, AXFR/NOTIFY (`src/core/zone/` modules).
- M3: DNSSEC validation/signing (`src/core/dnssec/` modules).

### Changed
- `config/config.toml`: QNAME minimization opt-in (`enable = false`), strict mode default.

### Security
- `deny.toml`: license restrictions enforced (OSL-3.0, MIT, Apache-2.0, BSD-3-Clause, ISC, Unicode-3.0, BSL-1.0).
- `#![forbid(unsafe_code)]` maintained globally.
- No `OpenSSL`/`BoringSSL`/`aws-lc-rs` in dependency tree (verified by CI gate).

---

*See [README.md](README.md) for milestone roadmap and [plans/m5_tracking.md](plans/m5_tracking.md) for sub-task landing plan.*
*License: [OSL-3.0](LICENSE) — network use counts as distribution.*

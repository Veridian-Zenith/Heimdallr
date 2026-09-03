# Heimdallr Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where applicable (pre-1.0 milestones use milestone tags).

## [0.4.0-alpha] — 2026-09-03

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

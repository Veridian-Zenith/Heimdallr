# Architecture

Heimdallr replaces `Technitium DNS Server` (`~/Work/Technitium/DnsServer/` + `TechnitiumLibrary/`) from zero in Rust. No `C#` or `TechnitiumLibrary.Net` code is reused; behavior is derived from RFCs via `hickory-proto`/`hickory-server` (`docs/rfcs.md`).

## Components and dependency direction

```
                 +----------------------+
                 |        heimdallr     |
                 |  binary (src/main.rs)|
                 +---^------+------^---+
                     |      |      |
         +-----------+  +---+---+  +-----------+
         |   net     |  |  core |  |   api     |
         | listeners |  | resolver| | axum :5380|
         | UDP/TCP/  |  | zones |  | zones/    |
         | TLS/QUIC/ |<->| cache |<->| DHCP/    |
         | HTTPS     |  | DNSSEC|  | cluster   |
         +--^--------+  +--^----+  +-----^-----+
            |              |             |
         +--+--------------+-------------+--+
         |  hickory-proto (dnssec-ring)    |
         |  quinn (ring) + rustls (ring)   |
         |  tokio (runtime)                |
         +---------------------------------+
```

**Rules (violations = design bug):**

1. `net` may not parse policy; it only frames (`PROXY v1/v2`, length-prefixed `TCP` `RFC 7766`) and hands bytes to `core`.
2. `core` is pure — same crate compiles for `cargo test` without `tokio` (like `Verdandi/policy/` host-testable). No `api` imports in `core`.
3. Siblings talk through `pub(crate)` channels/`mpsc`, never `Arc<Mutex<SharedState>>` across milestones.
4. Crypto is `ring` only in `default` build. `Botan` (`botan` crate, `botan-crypto` feature) is an alternate backend behind `trait DnssecProvider`; never `openssl`/`boring` in default.

## Repo-extraction contract (mirrors `Verdandi/docs/architecture.md:25-37`)

Every top-level future crate is extractable:

- own `Cargo.toml` with `if workspace` guard, own `README.md`, tests inside it.
- `git filter-repo --subdirectory-filter src/core` yields a reusable resolver lib.

## Module map (planned, `src/`)

```
src/
  main.rs       CLI (clap) + tracing init (ROADMAP.md:M0)
  net/
    udp.rs      tokio::net::UdpSocket + recvmmsg batching
    tcp.rs      length-prefixed framing, pipelined answers (RFC 7766 §6.2)
    tls.rs      rustls (ring) DoT RFC 7858
    quic.rs     quinn (ring) DoQ RFC 9250 (no libmsquic)
    doh.rs      axum + h2 DoH RFC 8484 (+h3 via quinn/h3 later)
    proxy.rs    PROXY protocol v1/v2 for UDP+TCP (Technitium parity)
  core/
    resolver.rs hickory-resolver wrapper + latency-based selection (concurrency)
    cache/      LRU + TTL, serve-stale, prefetch (ROADMAP.md:M1)
    zone/       primary/secondary/conditional/forwarder, AXFR/IXFR/NOTIFY/cat 9432
    dnssec/     validation (ring) + optional botan, signing, DANE/TLSA/SSHFP
    filter/     blocklists (regex, per-client), CNAME cloaking (AdvancedBlocking)
    rec/        QNAME min 9156 + case randomization, ECS 7871
  api/          Axum :5380 parity DnsServer/APIDOCS.md + DnsServerCore/WebService*.cs
  dhcp/         DHCPv4/v6 pools (M8)
  cluster/      control plane (M8)
  apps/         WASM-sandboxed DnsApp trait (future, mirrors DnsServer/Apps/ per-app Cargo but WASM)
```

## Crypto choice

Default: `ring` (`hickory-proto:dnssec-ring` `RSA`/`ECDSA`/`EdDSA` + `rustls:ring` + `quinn:ring`). Verified `cargo tree | grep -i openssl` empty (see `README.md:7`). Alternative: `botan` crate version `0.11` gating `DnssecProvider::Botan` (C++ `libbotan-2` dep, `RUSTFLAGS` unchanged). `aws-lc-rs`/`BoringSSL` explicitly banned in default.

## Decisions log

Append-only, newest last. Format: `YYYY-MM-DD — decision — reason`.

- 2026-08-29 — Pure Rust QUIC/TLS via `quinn`+`rustls` (`ring`), not `libmsquic` — `Technitium` `DnsServer/build.md:38` requires `libmsquic` on Linux; pure stack removes native dep and keeps `cargo tree` `openssl`-free.
- 2026-08-29 — Botan as optional feature, not default — user preference "`Botan or other if possible/needed rather than openssl/boringssl`"; `ring` covers ~95% DNSSEC/TLS, `Botan` reserved for HSM/agility without pulling `C++` into default.
- 2026-08-29 — `hickory-* 0.25` baseline — most Rok parity to `SupportedRFCs.md`, `ring` backend matches `TechnitiumLibrary.Security.*` RSA/ECDSA/EdDSA.
- 2026-08-29 — No `AGENTS.md` — `.gitignore:AGENTS.md` is ignored repo-wide (Verdandi rule); use `CONTRIBUTING.md`+`docs/architecture.md` as handbook.

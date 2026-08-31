# Architecture

Heimdallr replaces Technitium DNS Server from zero in Rust. No C# code is reused; behavior is derived from RFCs via `hickory-proto`/`hickory-server`.

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

1. `net` may not parse policy; it only frames (PROXY v1/v2, length-prefixed TCP RFC 7766) and hands bytes to `core`.
2. `core` is pure — same crate compiles for `cargo test` without `tokio`. No `api` imports in `core`.
3. Siblings talk through `pub(crate)` channels/`mpsc`, never `Arc<Mutex<SharedState>>` across milestones.
4. Crypto is `ring` only in default build. `Botan` is an alternate backend behind `trait DnssecProvider`; never `openssl`/`boring` in default.

## Module map (planned, `src/`)

```
src/
  main.rs       CLI (clap) + tracing init
  net/
    udp.rs      tokio::net::UdpSocket + recvmmsg batching
    tcp.rs      length-prefixed framing, pipelined answers (RFC 7766 §6.2)
    tls.rs      rustls (ring) DoT RFC 7858
    quic.rs     quinn (ring) DoQ RFC 9250
    doh.rs      axum + h2 DoH RFC 8484
    proxy.rs    PROXY protocol v1/v2
  core/
    resolver.rs hickory-resolver wrapper
    cache/      LRU + TTL, serve-stale, prefetch
    zone/       primary/secondary/conditional/forwarder, AXFR/IXFR/NOTIFY
    dnssec/     validation (ring) + optional botan, signing
    filter/     blocklists (regex, per-client), CNAME cloaking
    rec/        QNAME min 9156 + case randomization, ECS 7871
  api/          Axum :5380 parity
  dhcp/         DHCPv4/v6 pools (M8)
  cluster/      control plane (M8)
  apps/         WASM-sandboxed DnsApp trait (future)
```

## Crypto choice

Default: `ring` (`hickory-proto:dnssec-ring` RSA/ECDSA/EdDSA + `rustls:ring` + `quinn:ring`). `cargo tree | grep -i openssl` must be empty. Alternative: `botan` crate behind `botan-crypto` feature. `aws-lc-rs`/`BoringSSL` banned in default.

## Decisions log

Append-only, newest last. Format: `YYYY-MM-DD — decision — reason`.

- 2026-08-29 — Pure Rust QUIC/TLS via `quinn`+`rustls` (`ring`), not `libmsquic` — removes native dep, keeps `cargo tree` `openssl`-free.
- 2026-08-29 — Botan as optional feature, not default — `ring` covers ~95% DNSSEC/TLS, `Botan` reserved for HSM/agility.
- 2026-08-29 — `hickory-* 0.26.1` baseline — most RFC parity, `ring` backend.
- 2026-08-29 — No `AGENTS.md` — use `CONTRIBUTING.md`+`docs/architecture.md` as handbook.

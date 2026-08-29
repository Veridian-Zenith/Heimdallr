# Threat Model

Heimdallr is a `DNS server` — every UDP packet is untrusted, every TCP/TLS/QUIC handshake is attacker-controlled before authentication. Model mirrors `Voix/THREATS.md` TCB framing but for `53/udp` + `853/tcp` + `443/tcp` + `5380/tcp`.

> Every claim backed by code in `src/net/`+`src/core/dnssec/` and `tests/` (see `docs/testing.md`); `cargo audit`+`cargo tree` checks are `CONTRIBUTING.md` gates.

## Trusted Computing Base

| Metric | Technitium (`C#` `DnsServer/`+`TechnitiumLibrary/`, ~365 `.cs`, `21M+5.7M`) | Heimdallr (Rust) |
|---|---|---|
| `LoC` | `~150k` `C#` + `BCL` + `libmsquic` native | `~8k` Rust + `hickory`/`quinn`/`rustls`/`ring` — minimal native |
| External `C` deps | `libmsquic` (`DTA`/`DoQ`) + `BCL` | `0` default (`ring` asm only); optional `libbotan-2` with `botan-crypto` |
| `OpenSSL` | via `BCL`/`libmsquic` chain | `0` (`cargo tree | grep openssl` empty) |
| Config | `JSON` + web API (`APIDOCS.md`) | `TOML` + typed `serde` (fails closed) |

## Threat actor

**Unauthenticated network attacker** sending crafted `UDP`/`TCP`/`TLS`/`QUIC`/`HTTPS` packets to `:53`/`:853`/`:443`; secondarily **authenticated `API` user** (`:5380`) attempting privilege escalation inside console.

## Attack surface

### 1. Packet parsing (`src/net/`, `hickory-proto`)
- **Risk:** Parser CVEs (len, label compression `192` pointer loops, `RDLENGTH` OOM, poisoned cache).
- **Mitigations:** Rust `forbid(unsafe_code)` except `ring` asm + `botan-sys`; `hickory-proto` fuzzed upstream; Heimdallr adds `proptest`+`libFuzzer` (`docs/testing.md`), `EDNS(0)` `bufsize` caps, max zone `RDLENGTH 64k` + `RRSIG` cap, panic=abort (`Cargo.toml:profile.release`).

### 2. Cache poisoning (off-path + on-path)
- **Risks:** `TXID`/`port` brute force, Kaminsky, `NS` glue hijack, `CNAME` cloaking bypass.
- **Mitigations:** Randomized `TXID`+`source port` (`tokio` `UdpSocket` `IP_TRANSPARENT` bind pool), `QNAME` minimization `RFC 9156` + `0x20` randomization (opt-in), `DNSSEC` validation default (`ROADMAP.md:M3`), `CNAME` cloaking block (`filter/cname_cloaking`), cache `poison` rate-limit by client `IP` (`NAC` like `TechnitiumLibrary.Net/NetworkAccessControl`).

### 3. Encrypted transports (`net/tls.rs`, `quic.rs`, `doh.rs`)
- **Risks:** `rustls`/`quinn` handshake DoS, `SNI` leak, downgrade to cleartext forwarder.
- **Mitigations:** `rustls:ring` (`aws-lc-rs` banned), `quinn:ring` (no `libmsquic` per `README.md:7`), `forward_protocol` pinned (`dot`/`doh`/`doq` — never opportunistic), `PROXY protocol` allowlist check (`proxy.allow`).

### 4. Zone transfers (`zone/`)
- **Risks:** Unauthorized `AXFR` dump, `IXFR` replay, unsigned `ZONEMD` bypass.
- **Mitigations:** `allow-transfer` `ACL` `IP` allowlist (like `Technitium` zone `Transfer` `TSIG` `RFC 8945`), `ZONEMD` verification for secondary (`ROADMAP.md:M9`), `NOTIFY` `ACL` check before `IXFR`.

### 5. Web API `:5380` (`api/`)
- **Risks:** Auth bypass, `API token` theft, `RBAC` bypass, `XSS` via console, `CSRF`.
- **Mitigations:** `argon2id` password hashes, `API tokens` `hmac` scoped + `RBAC` (auditor cannot `POST /api/deleteZone` `ROADMAP.md:M7` gate), `TOTP` (`M7`) + optional `OIDC`, `axum` `tower` `CORS` deny-by-default + `CSRF` double-submit, `CSP` headers, `RateLimit` on `/api/login`.

### 6. Configuration tampering (`/etc/heimdallr/heimdallr.toml`)
- **Mitigations:** Owner `root:heimdallr` `0640`, path traversal rejection in `api` zone-file upload, `O_NOFOLLOW` on reads (same as `Voix/FileUtils` lineage), `--check-config` fails closed.

### 7. Persistence (`cache.bin`, `zones/`)
- **Mitigations:** `cache.bin` written with `0600`, validated header before load, `query.log` rotation with `O_APPEND`+`fstat` inode check (forge-resistant like `Voix/Logger`), symlink-resistant `open`.

### 8. Supply chain
- **Mitigations:** `Cargo.lock` committed, `cargo audit`+`cargo deny` in CI (`CONTRIBUTING.md`), `cargo tree` `openssl` ban gate, `Botan` only behind `botan-crypto` feature (isolates `C++` `libbotan-2`).

## Summary comparison

| Vector | Technitium posture | Heimdallr |
|---|---|---|
| Parser memory | `C#` `GC` safe but large `BCL` surface | `Rust` `no GC`, `ring` asm-only |
| `DoQ` native deps | `libmsquic` (`build.md:38`) | `quinn` pure (no `libmsquic`) |
| Crypto agility | `TechnitiumLibrary.Security.Cryptography` `C#` | `ring` default, `Botan` opt-in |
| Network amplification | Rate-limit per deployment | `NAC` + `QNAME` min + `DNSSEC` default + `tracing` |

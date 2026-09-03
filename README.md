<p align="center">
  <strong>Heimdallr</strong><br>
  <em>Watcher at the Bifrost</em>
</p>

<h3 align="center">Privacy & security DNS server — from-zero Rust</h3>

<p align="center">
  <a href="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml"><img src="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml"><img src="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-OSL--3.0-blue" alt="License"></a>
</p>

---

<p align="center">
  <a href="src/core/resolver/qname_min.rs"><img src="https://img.shields.io/badge/M5.4-QNAME%20min%20%E2%9C%93%20RFC%209156-2ea44f?style=for-the-badge" alt="M5.4 QNAME minimization"></a>
  <a href="tests/qname-min-validate.sh"><img src="https://img.shields.io/badge/gate-qname--min--validate-1f6feb?style=for-the-badge" alt="validation gate"></a>
  <a href="plans/m5_design.md"><img src="https://img.shields.io/badge/design-m5_design.md-orange?style=for-the-badge" alt="design doc"></a>
</p>

<p align="center">
  🛡️ <strong>opt-in</strong>
  &nbsp;·&nbsp;
  🔬 peels <code>com.</code> → <code>example.com.</code> → <code>…</code>
  &nbsp;·&nbsp;
  🔁 falls back on every-step error
  &nbsp;·&nbsp;
  ⚙️ default <code>enable = false</code>
</p>

---

From-zero Rust DNS server built to replace [Technitium DNS Server](https://technitium.com/) long-term. No code copied — wire format implemented from RFCs via `hickory-proto`/`hickory-server`.

**Pure `ring` + `quinn`/`rustls` + `Botan`** — no `OpenSSL`/`BoringSSL`/`aws-lc-rs` in default build.

| | |
|---|---|
| **Binary** | `heimdallr` (single static binary, Linux) |
| **License** | `OSL-3.0` — network use counts as distribution |
| **Status** | `0.4.0-alpha` — M0 ✅ M1 ✅ M2 ✅ M3 ✅ M4 ✅ **M5.4 ✅** (see [CHANGELOG.md](CHANGELOG.md)) |

---

## Table of Contents

<details open>
<summary><strong>Contents</strong></summary>

- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Operation](#operation)
- [RFC Coverage](#rfc-coverage)
- [Threat Model](#threat-model)
- [Comparison vs Technitium](#comparison-vs-technitium)
- [Performance](#performance)
- [Lessons from Technitium](#lessons-from-technitium)
- [Testing & Quality Gates](#testing--quality-gates)
- [Contributing](#contributing)
- [Security](#security)
- [Branding](#branding)
- [Changelog](CHANGELOG.md)
- [License](#license)
- [Contact](#contact)

</details>

---

## Architecture

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
         |  botan (HSM/agile crypto)       |
         |  tokio (runtime)                |
         +---------------------------------+
```

**Design rules** (violations = design bug):

| # | Rule |
|---|------|
| 1 | `net` may not parse policy — it only frames (PROXY v1/v2, length-prefixed TCP RFC 7766) and hands bytes to `core`. |
| 2 | `core` is pure — same crate compiles for `cargo test` without `tokio`. No `api` imports in `core`. |
| 3 | Siblings talk through `pub(crate)` channels/`mpsc`, never `Arc<Mutex<SharedState>>` across milestones. |
| 4 | Crypto is `ring` + `botan` in default build. `aws-lc-rs`/`BoringSSL`/`OpenSSL` banned in default. |

### Module map

```
src/
  main.rs       CLI (clap) + tracing init
  net/
    udp.rs      tokio::net::UdpSocket + recvmmsg batching
    tcp.rs      PROXY-aware TCP DNS (RFC 7766 §6.2) + pipelined answers
    proxy.rs    PROXY protocol v1/v2 parser
    cert.rs     TLS certificate loading + self-signed generation
    handler.rs  HeimdallrHandler — wraps Catalog with NOTIFY interception
    mod.rs      hickory-server listeners (UDP/TCP/DoT/DoH/DoQ) + PROXY TCP spawn
  core/
    resolver/   hickory-resolver wrapper + DNSSEC validation + QNAME minimization (M5.4)
    cache/      LRU + TTL, serve-stale, prefetch
    zone/       primary/secondary/catalog, AXFR/IXFR/NOTIFY, record CRUD
    dnssec/     validation (ring) + signing + key management (botan optional)
    filter/     blocklists (regex, per-client), CNAME cloaking (M6)
  api/          Axum :5380 — health, zones, records, TLSA CRUD, API TLS (rustls)
  dhcp/         DHCPv4/v6 pools (M8)
  cluster/      control plane (M8)
  apps/         WASM-sandboxed DnsApp trait (future)
```

### Module dependency direction

```
main.rs → net + core + api
net     → core (zones, cache, resolver)
core    → hickory-proto, hickory-server, hickory-resolver
api     → core (zone configs), config
```

---

## Roadmap

Milestones are gates — do not start `M(n+1)` before `M(n)` passes. Linux-only; Windows deferred.

### Completed

| Milestone | Scope | Status |
|-----------|-------|--------|
| **M0** Scaffold | `Cargo.toml`, `--help`, `LICENSE`, docs tree | ✅ |
| **M1** UDP/TCP Recursive + Cache | `hickory-resolver`, `CacheForwardAuthority` LRU+TTL, EDNS(0), extended errors, serve-stale, prefetch | ✅ |
| **M2** Authoritative Zones + Transfers | Primary/Secondary zones, AXFR serving + client, NOTIFY handler, catalog zones RFC 9432, API `/api/zones` | ✅ |
| **M3** DNSSEC Validation & Signing | Validation via `TrustAnchors`, ECDSA/Ed25519 key generation, zone signing (`RRSIG`/`DNSKEY`/`NSEC`/`NSEC3`), DANE TLSA CRUD, NSEC3 config | ✅ |
| **M4** Encrypted Transports | DoT RFC 7858 (`rustls:ring`), DoH RFC 8484 (`h2`), DoQ RFC 9250 (`quinn:ring`), PROXY protocol v1/v2, forwarder routing over DoT/DoH/DoQ, API TLS | ✅ |
| **M5.4** QNAME Minimization | RFC 9156 incremental label-peeling in [`src/core/resolver/qname_min.rs`](src/core/resolver/qname_min.rs), opt-in (`resolver.qname_minimization.enable`), fallback to full-QNAME on every-step error, mode selector (`incremental`/`aggressive`/`strict`), 10 unit tests + [`tests/qname-min-validate.sh`](tests/qname-min-validate.sh) | ✅ |

### In progress

| Milestone | Scope | Gate |
|-----------|-------|------|
| **M5** Advanced Records & Behaviors | SVCB/HTTPS ✅, SSHFP ✅, URI, DNAME, ANAME (apex CNAME flattening), case randomization, CNAME cloaking, DANE hash auto-gen, DNS64, EDNS Client Subnet | M5.1 + M5.2 landed |

### Planned

| Milestone | Scope |
|-----------|-------|
| **M6** Filtering, Apps & Observability | Blocklist URLs, regex per-client, DnsBlockList, BlockPage sinkhole, DNS Rebinding Protection, persistent cache, stats + query logs, Prometheus metrics, full HTTP API |
| **M7** Administration & Hardening | Web console (axum + static files, dark mode), multi-user RBAC + API tokens, TOTP 2FA, OIDC SSO, system logging, split-horizon/geo via Apps |
| **M8** Auxiliary Services | Built-in DHCP server, HTTP/SOCKS5 proxy routing (incl. Tor), clustering, Docker, systemd |
| **M9** Full Parity & Migration | XFR-over-TLS/QUIC, TSIG RFC 8945, Dynamic Updates RFC 2136, WeightedRoundRobin/Failover apps, Technitium zone JSON import, benchmark target: >60k qps |

<details>
<summary><strong>Roadmap gate commands</strong></summary>

| Milestone | Gate command |
|-----------|-------------|
| M0 | `cargo check && cargo build --release` |
| M1 | `dig @127.0.0.1:5353 example.com` — answer from upstream, second query cached (<1ms) |
| M2 | AXFR over TCP, NOTIFY triggers re-AXFR, `cargo test` 41+ tests |
| M3 | `delv @127.0.0.1` validates signed zones, `ldns-verify-zone` passes |
| M4 | `kdig -d @127.0.0.1 +tls`, `curl --doh-url https://127.0.0.1/dns-query`, QUIC client all resolve |
| M5.4 | `./tests/qname-min-validate.sh` (requires `RUST_LOG=heimdallr=debug` for trace assertion) |

</details>

---

## Quick Start

```bash
# Build
cargo build --release          # -> target/release/heimdallr

# Run with defaults (binds 0.0.0.0:53, recursive via 1.1.1.1/8.8.8.8)
RUST_LOG=info heimdallr

# Validate config without binding ports
heimdallr --check-config

# Custom config
heimdallr --config /etc/heimdallr/config.toml

# Enable QNAME minimization (opt-in, M5.4)
# Add to [resolver] in config.toml:
#   qname_minimization.enable = true
#   qname_minimization.mode    = "strict"   # or "incremental" | "aggressive"
#   qname_minimization.max_iterations = 7
```

---

## Configuration

Heimdallr reads TOML at `/etc/heimdallr/config.toml` by default. CLI `--config` overrides. Missing keys use defaults.

> [!NOTE]
> Run `heimdallr --check-config` to validate config without binding ports.

### Config reference

<details>
<summary><strong>Full config.toml reference</strong></summary>

```toml
# Network
listen = ["0.0.0.0:53", "[::]:53"]
listen_tls = ["0.0.0.0:853"]       # DoT (M4)
listen_quic = ["0.0.0.0:853"]      # DoQ (M4)
listen_https = ["0.0.0.0:443"]     # DoH (M4)

# Server hostname — used for SOA NS, Let's Encrypt cert auto-detection
host = "ns1.example.test."

# Zone admin email (SOA RNAME). Default: hostadmin@<host>.
# hostadmin = "admin@mynetwork.test"

# Zone files directory
zones_dir = "/etc/heimdallr/zones"

# TLS — auto-detects Let's Encrypt certs from /etc/letsencrypt/live/<host>/
[tls]
# cert = "/path/to/fullchain.pem"
# key = "/path/to/privkey.pem"
# letsencrypt_dir = "/etc/letsencrypt/live"

# Recursive resolver
[resolver]
forwarders = ["1.1.1.1:53", "8.8.8.8:53"]
forward_protocol = "udp"         # udp|tcp|dot|doh|doq

# QNAME minimization (M5.4, RFC 9156) — opt-in. Default enable=false.
# When enabled, the forwarder issues one query per label step
# (com. -> example.com. -> -> original name) instead of a single
# full-QNAME lookup. Falls back to the unminimized query if every
# peel step errors. Modes: incremental | aggressive | strict.
[resolver.qname_minimization]
# enable = false
# mode = "strict"
# max_iterations = 7

qname_randomization = false
ecs = false
concurrency = 2
timeout_ms = 2000

# Cache
[cache]
size = 50000
serve_stale = true
prefetch = 2
# persistent = "/var/lib/heimdallr/cache.bin"

# DNSSEC
[dnssec]
validation = true               # validate upstream responses
signing = false                 # global signing flag
provider = "ring"               # ring|botan

# DNSSEC key management
[dnssec_keys]
keys_dir = "/var/lib/heimdallr/keys"
# trust_anchor = "/var/lib/heimdallr/root-anchors.xml"

# Filtering (M6)
[filter]
blocklists = []
allowlists = []
regex_blocklist = []
# per_client = { "10.0.0.5/32" = { block = false } }
cname_cloaking = true
rebinding = true

# PROXY protocol (M4)
[proxy]
enable = false
allow = []
protocol = "v2"                  # v1|v2

# API
[api]
listen = "127.0.0.1:5380"
# tls_cert = ""
# tls_key = ""

# Auth (M7)
[auth]
# users = [{ name = "admin", password_hash = "$argon2id$..." }]
# tokens = []
totp = false
oidc = false

# Logging
[log]
level = "info"                   # trace|debug|info|warn|error
query_log = ""                   # path to query log file
format = "json"                  # json|text

# DHCP (M8)
[dhcp]
enable = false
# ranges = [{ subnet = "10.0.0.0/24", start = "10.0.0.100", end = "10.0.0.200", router = "10.0.0.1" }]

# Clustering (M8)
[cluster]
enable = false
# peers = []

# Zones
[[zones]]
name = "example.test."
kind = "primary"                 # primary|secondary|stub|conditional|forwarder
file = "example.test.zone"
dnssec_signing = true
dnssec_algorithm = "ecdsa-p256"  # ecdsa-p256|ecdsa-p384|ed25519|rsa-sha256

# NSEC3 configuration (optional)
# [zones.nx_proof]
# kind = "nsec3"                 # nsec|nsec3
# iterations = 0
# salt = ""                      # hex-encoded
# opt_out = false

[[zones]]
name = "10.in-addr.arpa."
kind = "primary"
file = "10.in-addr.arpa.zone"
```

</details>

---

## API Reference

All endpoints return JSON. API listens on `127.0.0.1:5380` by default.

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | `{"status":"ok","version":"0.4.0-alpha"}` |
| `GET` | `/api/info` | Server info — hostname, listen addrs, zones count, DNSSEC, cache, log level |

### Zones

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/zones` | List all configured zones |
| `GET` | `/api/zones/{name}` | Zone detail (name, kind, file, primaries) |

### Records (M3)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/zones/{name}/records` | List all records in zone |
| `GET` | `/api/zones/{name}/records/{type}` | Get records by type |
| `POST` | `/api/zones/{name}/records` | Create record (JSON body: `{name, record_type, ttl, data}`) |
| `POST` | `/api/zones/{name}/records/delete` | Delete records (JSON body: `{name, record_type}`) |

**TLSA record example:**

```bash
# Add DANE TLSA record
curl -X POST http://127.0.0.1:5380/api/zones/example.test./records \
  -H 'Content-Type: application/json' \
  -d '{"name":"_443._tcp.www","record_type":"TLSA","ttl":3600,"data":"3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"}'
```

---

## Operation

### Install

```bash
sudo ./scripts/install.sh
```

The install script builds the release binary, creates the `heimdallr` user/group, and installs all files. It detects existing config/zone/systemd files and prompts before overwriting — declined files are placed in `/opt/heimdallr/zones/templates/`.

### systemd

```bash
sudo systemctl disable --now systemd-resolved  # if in use
sudo systemctl enable --now heimdallr
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
journalctl -u heimdallr -f
```

> [!IMPORTANT]
> These commands disable `systemd-resolved`. Make sure no other service depends on it.

### CLI

```bash
heimdallr --help
heimdallr --check-config
heimdallr --config /etc/heimdallr/config.toml --listen 127.0.0.1:5353
RUST_LOG=heimdallr=debug,quinn=info heimdallr
```

### Build verification

```bash
cargo build --release
cargo tree | grep -iE "openssl|bssl|aws-lc"   # must be empty
cargo audit
```

---

## RFC Coverage

### Core wire

| RFC | Title | Status |
|-----|-------|--------|
| 1035 + 1034 | DNS base | ✅ M1 — `hickory-proto` |
| 6891 | EDNS(0) | ✅ M1 |
| 7766 | DNS over TCP (+ pipelining §7) | ✅ M1 |
| 8482 | ANY RCODE | ✅ M1 |

### DNSSEC

| RFC | Title | Status |
|-----|-------|--------|
| 4033–4035 | DNSSEC validation/signing | ✅ M3 — `ring` |
| 5155 | NSEC3 | ✅ M3 |
| 6698 | DANE TLSA | ✅ M3 — CRUD API |
| 8976 | ZONEMD | Deferred to M9 |
| 8945 | TSIG | M9 |
| 9103 | XFR-over-TLS | M9 |

### Encrypted transports

| RFC | Title | Status |
|-----|-------|--------|
| 7858 | DoT | ✅ M4 — `rustls:ring` |
| 8484 | DoH | ✅ M4 — `hickory h2` |
| 9250 | DoQ | ✅ M4 — `quinn:ring` |
| — | PROXY protocol v1/v2 | ✅ M4 |
| — | API TLS | ✅ M4 — `tokio-rustls:ring` |

### Zones & transfers

| RFC | Title | Status |
|-----|-------|--------|
| 5936 | AXFR | ✅ M2 |
| 1996 | NOTIFY | ✅ M2 |
| 9432 | Catalog zones | ✅ M2 |
| 2136 | Dynamic Updates | M9 |

### Records & behaviors

| RFC | Title | Status |
|-----|-------|--------|
| 9156 | QNAME minimization | ✅ **M5.4** — `qname_min.rs` (opt-in) |
| 7871 | EDNS Client Subnet | M5 |
| 8914 | Extended DNS Errors | ✅ M1 |
| 7314 | EDNS EXPIRE | M5 |
| 9460 | SVCB/HTTPS | M5 |
| 7553 | URI | M5 |
| 4255 | SSHFP | ✅ M5.2 |
| 6672 | DNAME | M5 |
| 6147 | DNS64 | M5 |

---

## Threat Model

Heimdallr is a DNS server — every UDP packet is untrusted, every TCP/TLS/QUIC handshake is attacker-controlled before authentication.

### Trusted Computing Base

| Metric | Value |
|--------|-------|
| Lines of Rust | ~10k + hickory/quinn/rustls/ring/botan |
| External C deps | 0 default (ring asm only); optional libbotan-2 |
| OpenSSL | 0 (`cargo tree | grep openssl` empty) |
| Config format | TOML + typed serde (fails closed) |
| Unsafe code | `#![forbid(unsafe_code)]` |

### Attack surface

| Surface | Risk | Mitigation |
|---------|------|------------|
| **Packet parsing** (`net/`, `hickory-proto`) | Parser CVEs, label compression loops, RDLENGTH OOM | Rust `forbid(unsafe)`, hickory fuzzed upstream, EDNS bufsize caps |
| **Cache poisoning** | TXID/port brute force, Kaminsky, NS glue hijack | Randomized TXID+port, **QNAME minimization (M5.4)**, DNSSEC (M3) |
| **Encrypted transports** | rustls/quinn handshake DoS, SNI leak | ring crypto, forward_protocol pinned, PROXY allowlist |
| **Zone transfers** | Unauthorized AXFR dump | allow-transfer ACL, ZONEMD (M9) |
| **Web API :5380** | Auth bypass, token theft, RBAC bypass | argon2id, HMAC tokens, RBAC, TOTP/OIDC (M7) |
| **Configuration** | Tampering | root:heimdallr 0640, path traversal rejection |
| **Persistence** | cache.bin tampering | 0600 perms, validated header, symlink-resistant |
| **Supply chain** | Dependency compromise | Cargo.lock committed, cargo audit/deny in CI |

---

## Comparison vs Technitium

| Area | Technitium | Heimdallr |
|------|-----------|-----------|
| Core | C# .NET, custom wire | Rust hickory (ring) |
| Runtime | GC + libmsquic | no GC, quinn+rustls |
| Crypto | C# crypto provider | ring + botan (no OpenSSL) |
| Cache | serve stale, prefetch, persistent | ✅ M1/M6 |
| DNSSEC | RSA/ECDSA/EdDSA, NSEC+NSEC3 | ✅ M3 via ring + botan |
| Encrypted | DoT/DoH/DoQ, PROXY v1/v2 | ✅ M4 |
| QNAME min | opt-in (always on by default) | ✅ **M5.4** opt-in (`enable=false` default) |
| Records | DANE, SVCB/HTTPS ✅, SSHFP ✅, URI, DNAME, ANAME, APP | ✅ DANE M3 · ✅ SVCB/HTTPS M5.1 · ✅ SSHFP M5.2 |
| Zones | Primary/Secondary/Stub/CondFwd + catalog, AXFR/IXFR/NOTIFY | ✅ M2 / M9 |
| Filter | AdvancedBlocking, DnsBlockList, BlockPage | M6 |
| Forwarding | Latency concurrency | resolver.concurrency + M9 |
| DHCP | multi-scope | M8 |
| Console | Web dashboard + REST API | axum :5380 M6–M7 |
| Auth | RBAC + tokens + TOTP + OIDC | M7 |
| Clustering | manage N instances | M8 |
| Apps | 27 per-app projects | WASM DnsApp trait |
| Bench | 100k req/s | >60k qps target M9 |

**License difference:** GPL-3.0 network use is not conveying. OSL-3.0 External Deployment forces hosted modifiers to publish source.

---

## Performance

| Metric | Value | Test |
|
|--------|-------|------|
| Cache lookup (hit) | <105 ns | criterion, 100 measurements |
| Cache lookup (miss) | <5 ns | criterion |
| Cache insert (256B) | <120 ns | criterion |
| PROXY v1 TCP4 parse | <50 ns | criterion |
| PROXY v2 TCP4 parse | <40 ns | criterion |

> Benchmarks in `benches/cache_bench.rs`. Target: >60k qps cached on i7-8700 class (M9).

---

## Lessons from Technitium

### What Technitium gets right

1. **Zero-config that still shows its work.** Stats + query logs make the network legible. Keep M6 logs+metrics first-class.
2. **Apps as the escape hatch.** AdvancedBlocking per-client regex + AdvancedForwarding + DnsBlockList + SplitHorizon mean power users never fork core.
3. **Forwarder concurrency over static priority.** Latency-based selection with concurrency is real-world snappy.
4. **Encrypted path parity.** DoT/DoH/DoQ as both self-hosted services and forwarder protocols is not optional.

### What to design out

| Scar | Technitium | Heimdallr |
|------|-----------|-----------|
| libmsquic native dep | `apt install libmsquic` | Pure quinn+rustls — zero native QUIC |
| GPL-3.0 hides hosted mods | Forks can run unpublished | OSL-3.0 — hosted keeps copyleft |
| C# crypto hides agility | Adding GOST/EdDSA = core rebuild | ring + botan-crypto trait |
| Query Logs PostgreSQL split | sqlite/mysql/mssql/pgsql fan-out | sqlite default + single PG exporter |
| Monolithic WebServiceApi | dashboard+zones/Logs/settings in one file | axum routed modules |
| ANAME/APP proprietary | No import story | M5 ANAME + M9 import |

### Tuning defaults

- Cache: serve-stale on, prefetch=2
- QNAME minimization off by default (opt-in via M5.4 — `enable=true` to activate); 0x20 off (middlebox compat)
- Forwarders: concurrency 2, timeout 2s
- Observability: query.log json + Prometheus (M6)

---

## Testing & Quality Gates

### Test levels

```bash
# Unit tests
cargo test
cargo test -- --nocapture
RUST_LOG=debug cargo test core::cache --nocapture

# QNAME minimization unit tests (M5.4)
cargo test --bin heimdallr qname_min

# Property & fuzz
cargo fuzz run dns_parse -- -max_total_time=60

# Integration (requires ports)
cargo test --test integration -- --ignored

# DNSSEC validation gate
./tests/dnssec-validate.sh

# QNAME minimization gate (M5.4)
RUST_LOG=heimdallr=debug ./tests/qname-min-validate.sh
```

### CI quality gates (must all pass)

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
cargo audit                # no advisories
cargo deny check           # bans ok, licenses ok, sources ok
cargo tree | grep -ivE "openssl|bssl|aws-lc"  # must be empty
```

---

## Contributing

Rules are short — Heimdallr is DNS, not a web toy.

- Open an issue for anything larger than a typo. State intent and affected milestone.
- One idea per PR.
- `rustfmt` default — do not debate.
- Comments only where code cannot speak. Short sentences, ASCII.
- No new dependency without an issue. List is intentionally tiny — `tokio`, `hickory-*`, `quinn`+`rustls` (`ring`), `botan`, `axum`, `hyper`, `hyper-util`, `tower`, `tokio-rustls`, `anyhow`, `clap`, `tracing`. Adding `openssl`/`boring`/`aws-lc` requires RFC-style justification.
- Commit messages: imperative (`Add QNAME minimization`), not `added`.

### Bugs & security

- Bugs with repro: issue → exact `cargo`/`dig`/`kdig` commands + `RUST_LOG=debug` output.
- Security: [SECURITY.md](SECURITY.md) private channel — never issues.

---

## Security

Heimdallr is a DNS server. Bugs here are network amplifiable, cache-poisonable, and privacy-breaking.

- **Report via** GitHub private security advisory, or [SECURITY.md](SECURITY.md) channels.
- **In scope:** cache poisoning, memory corruption from crafted packets, API auth bypass, DNSSEC bypass, privilege escalation, supply-chain regression.
- **Out of scope:** DoS by flooding `127.0.0.1:53` without amplification/poisoning vector, social engineering, physical access.

See [SECURITY.md](SECURITY.md) for full details.

---

## Branding

**Heimdallr** — Old Norse. The god who watches the bridge.

- **Name:** `Heimdallr` (capital H, lower r terminal). Binary: `heimdallr`. Service: `heimdallr.service`.
- **Mark:** `H` formed from `Hagall` rune + bridge arch, stroke Amber (#f59e0b) on Void Black (#0a0a0a).
- **Rules:** Do not use marks to endorse a fork without written permission. Derivative web consoles must replace the loading screen sigil.

---

## License

**Open Software License 3.0** — see [LICENSE](LICENSE).

```
Copyright (c) 2026 Veridian Zenith
```

- **Use freely**, including commercially.
- **Network use = distribution.** External Deployment (LICENSE §28) means hosted modifiers must publish source under OSL-3.0.
- **Derivative works stay OSL-3.0.**
- **Keep attribution.** Retain copyright notices. Add "Modified by ... on ..." to changed files.

---

## Contact

- **Email:** [daedaevibin@ik.me](mailto:daedaevibin@ik.me)
- **Matrix:** [@daedaevibin:matrix.org](https://matrix.to/@daedaevibin:matrix.org)
- **Mastodon:** [@daedaevibin@defcon.social](https://defcon.social/@daedaevibin)
- **Discord:** [Veridian Zenith](https://discord.gg/Vprc6XRkRg) (email [daedaevibin@ik.me](mailto:daedaevibin@ik.me) when you join)
- **Repo:** [github.com/Veridian-Zenith/Heimdallr](https://github.com/Veridian-Zenith/Heimdallr)

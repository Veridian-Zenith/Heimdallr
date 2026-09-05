1|<p align="center">
2|  <strong>Heimdallr</strong><br>
3|  <em>Watcher at the Bifrost</em>
4|</p>
5|
6|<h3 align="center">Privacy & security DNS server — from-zero Rust</h3>
7|
8|<p align="center">
9|  <a href="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml"><img src="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
10|  <a href="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml"><img src="https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml/badge.svg" alt="Release"></a>
11|  <a href="LICENSE"><img src="https://img.shields.io/badge/license-OSL--3.0-blue" alt="License"></a>
12|</p>
13|
14|---
15|
16|<p align="center">
17|  <a href="src/core/resolver/qname_min.rs"><img src="https://img.shields.io/badge/M5.4-QNAME%20min%20%E2%9C%93%20RFC%209156-2ea44f?style=for-the-badge" alt="M5.4 QNAME minimization"></a>
18|  <a href="tests/qname-min-validate.sh"><img src="https://img.shields.io/badge/gate-qname--min--validate-1f6feb?style=for-the-badge" alt="validation gate"></a>
19|  <a href="plans/m5_design.md"><img src="https://img.shields.io/badge/design-m5_design.md-orange?style=for-the-badge" alt="design doc"></a>
20|</p>
21|
22|<p align="center">
23|  🛡️ <strong>opt-in</strong>
24|  &nbsp;·&nbsp;
25|  🔬 peels <code>com.</code> → <code>example.com.</code> → <code>…</code>
26|  &nbsp;·&nbsp;
27|  🔁 falls back on every-step error
28|  &nbsp;·&nbsp;
29|  ⚙️ default <code>enable = false</code>
30|</p>
31|
32|---
33|
34|From-zero Rust DNS server built to replace [Technitium DNS Server](https://technitium.com/) long-term. No code copied — wire format implemented from RFCs via `hickory-proto`/`hickory-server`.
35|
36|**Pure `ring` + `quinn`/`rustls` + `Botan`** — no `OpenSSL`/`BoringSSL`/`aws-lc-rs` in default build.
37|
38|| | |
39||---|---|
40|| **Binary** | `heimdallr` (single static binary, Linux) |
41|| **License** | `OSL-3.0` — network use counts as distribution |
42|| **Status** | `0.7.3-alpha` — M0 ✅ M1 ✅ M2 ✅ M3 ✅ M4 ✅ M5 ✅ M6 ✅ M7.1 ✅ M7.2 ✅ M7.3 ✅ (runtime toggle endpoint with auth gate) |
43|
44|---
45|
46|## Table of Contents
47|
48|<details open>
49|<summary><strong>Contents</strong></summary>
50|
51|- [Architecture](#architecture)
52|- [Roadmap](#roadmap)
53|- [Quick Start](#quick-start)
54|- [Configuration](#configuration)
55|- [API Reference](#api-reference)
56|- [Operation](#operation)
57|- [RFC Coverage](#rfc-coverage)
58|- [Threat Model](#threat-model)
59|- [Comparison vs Technitium](#comparison-vs-technitium)
60|- [Performance](#performance)
61|- [Lessons from Technitium](#lessons-from-technitium)
62|- [Testing & Quality Gates](#testing--quality-gates)
63|- [Contributing](#contributing)
64|- [Security](#security)
65|- [Branding](#branding)
66|- [Changelog](CHANGELOG.md)
67|- [License](#license)
68|- [Contact](#contact)
69|
70|</details>
71|
72|---
73|
74|## Architecture
75|
76|```
77|                 +----------------------+
78|                 |        heimdallr     |
79|                 |  binary (src/main.rs)|
80|                 +---^------+------^---+
81|                     |      |      |
82|         +-----------+  +---+---+  +-----------+
83|         |   net     |  |  core |  |   api     |
84|         | listeners |  | resolver| | axum :5380|
85|         | UDP/TCP/  |  | zones |  | zones/    |
86|         | TLS/QUIC/ |<->| cache |<->| DHCP/    |
87|         | HTTPS     |  | DNSSEC|  | cluster   |
88|         +--^--------+  +--^----+  +-----^-----+
89|            |              |             |
90|         +--+--------------+-------------+--+
91|         |  hickory-proto (dnssec-ring)    |
92|         |  quinn (ring) + rustls (ring)   |
93|         |  botan (HSM/agile crypto)       |
94|         |  tokio (runtime)                |
95|         +---------------------------------+
96|```
97|
98|**Design rules** (violations = design bug):
99|
100|| # | Rule |
101||---|------|
102|| 1 | `net` may not parse policy — it only frames (PROXY v1/v2, length-prefixed TCP RFC 7766) and hands bytes to `core`. |
103|| 2 | `core` is pure — same crate compiles for `cargo test` without `tokio`. No `api` imports in `core`. |
104|| 3 | Siblings talk through `pub(crate)` channels/`mpsc`, never `Arc<Mutex<SharedState>>` across milestones. |
105|| 4 | Crypto is `ring` + `botan` in default build. `aws-lc-rs`/`BoringSSL`/`OpenSSL` banned in default. |
106|
107|### Module map
108|
109|```
110|src/
111|  main.rs       CLI (clap) + tracing init
112|  net/
113|    udp.rs      tokio::net::UdpSocket + recvmmsg batching
114|    tcp.rs      PROXY-aware TCP DNS (RFC 7766 §6.2) + pipelined answers
115|    proxy.rs    PROXY protocol v1/v2 parser
116|    cert.rs     TLS certificate loading + self-signed generation
117|    handler.rs  HeimdallrHandler — wraps Catalog with NOTIFY interception
118|    mod.rs      hickory-server listeners (UDP/TCP/DoT/DoH/DoQ) + PROXY TCP spawn
119|  core/
120|    resolver/   hickory-resolver wrapper + DNSSEC validation + QNAME minimization (M5.4)
121|    cache/      LRU + TTL, serve-stale, prefetch
122|    zone/       primary/secondary/catalog, AXFR/IXFR/NOTIFY, record CRUD
123|    dnssec/     validation (ring) + signing + key management (botan optional)
124|    filter/     blocklists (regex, per-client), CNAME cloaking (M6)
125|  api/          Axum :5380 — health, zones, records, TLSA CRUD, API TLS (rustls)
126|  dhcp/         DHCPv4/v6 pools (M8)
127|  cluster/      control plane (M8)
128|  apps/         WASM-sandboxed DnsApp trait (future)
129|```
130|
131|### Module dependency direction
132|
133|```
134|main.rs → net + core + api
135|net     → core (zones, cache, resolver)
136|core    → hickory-proto, hickory-server, hickory-resolver
137|api     → core (zone configs), config
138|```
139|
140|---
141|
142|## Roadmap
143|
144|Milestones are gates — do not start `M(n+1)` before `M(n)` passes. Linux-only; Windows deferred.
145|
146|### Completed
147|
148|| Milestone | Scope | Status |
149||-----------|-------|--------|
150|| **M0** Scaffold | `Cargo.toml`, `--help`, `LICENSE`, docs tree | ✅ |
151|| **M1** UDP/TCP Recursive + Cache | `hickory-resolver`, `CacheForwardAuthority` LRU+TTL, EDNS(0), extended errors, serve-stale, prefetch | ✅ |
152|| **M2** Authoritative Zones + Transfers | Primary/Secondary zones, AXFR serving + client, NOTIFY handler, catalog zones RFC 9432, API `/api/zones` | ✅ |
153|| **M3** DNSSEC Validation & Signing | Validation via `TrustAnchors`, ECDSA/Ed25519 key generation, zone signing (`RRSIG`/`DNSKEY`/`NSEC`/`NSEC3`), DANE TLSA CRUD, NSEC3 config | ✅ |
154|| **M4** Encrypted Transports | DoT RFC 7858 (`rustls:ring`), DoH RFC 8484 (`h2`), DoQ RFC 9250 (`quinn:ring`), PROXY protocol v1/v2, forwarder routing over DoT/DoH/DoQ, API TLS | ✅ |
155|| **M5.4** QNAME Minimization | RFC 9156 incremental label-peeling in [`src/core/resolver/qname_min.rs`](src/core/resolver/qname_min.rs), opt-in (`resolver.qname_minimization.enable`), fallback to full-QNAME on every-step error, mode selector (`incremental`/`aggressive`/`strict`), 10 unit tests + [`tests/qname-min-validate.sh`](tests/qname-min-validate.sh) | ✅ |
156|
157|### In progress
158|
159|| Milestone | Scope | Gate |
160||-----------|-------|------|
161|| **M5** Advanced Records & Behaviors | SVCB/HTTPS ✅, SSHFP ✅, URI, DNAME, ANAME (apex CNAME flattening), case randomization, CNAME cloaking, DANE hash auto-gen, DNS64, EDNS Client Subnet | M5.1 + M5.2 landed |
162|
163|### Planned
164|
165|| Milestone | Scope |
166||-----------|-------|
167|| **M6** Filtering, Apps & Observability | Blocklists (hosts/AdGuard/meta-list) ✅, regex per-client ✅, persistent cache (`cache.bin` JSON) ✅, query log (`dns_logs` PG table) ✅, Prometheus metrics (OpenMetrics) ✅, full HTTP API (stub), sinkhole config ✅, per-client ACL (CIDR) ✅ | v0.6.5-alpha |
168|| **M7** Administration & Hardening | Web console (axum + static files, dark mode), multi-user RBAC + API tokens, TOTP 2FA, OIDC SSO, system logging, split-horizon/geo via Apps |
169|| **M8** Auxiliary Services | Built-in DHCP server, HTTP/SOCKS5 proxy routing (incl. Tor), clustering, Docker, systemd |
170|| **M9** Full Parity & Migration | XFR-over-TLS/QUIC, TSIG RFC 8945, Dynamic Updates RFC 2136, WeightedRoundRobin/Failover apps, Technitium zone JSON import, benchmark target: >60k qps |
171|
172|<details>
173|<summary><strong>Roadmap gate commands</strong></summary>
174|
175|| Milestone | Gate command |
176||-----------|-------------|
177|| M0 | `cargo check && cargo build --release` |
178|| M1 | `dig @127.0.0.1:5353 example.com` — answer from upstream, second query cached (<1ms) |
179|| M2 | AXFR over TCP, NOTIFY triggers re-AXFR, `cargo test` 41+ tests |
180|| M3 | `delv @127.0.0.1` validates signed zones, `ldns-verify-zone` passes |
181|| M4 | `kdig -d @127.0.0.1 +tls`, `curl --doh-url https://127.0.0.1/dns-query`, QUIC client all resolve |
182|| M5.4 | `./tests/qname-min-validate.sh` (requires `RUST_LOG=heimdallr=debug` for trace assertion) |
183|
184|</details>
185|
186|---
187|
188|## Quick Start
189|
190|```bash
191|# Build
192|cargo build --release          # -> target/release/heimdallr
193|
194|# Run with defaults (binds 0.0.0.0:53, recursive via 1.1.1.1/8.8.8.8)
195|RUST_LOG=info heimdallr
196|
197|# Validate config without binding ports
198|heimdallr --check-config
199|
200|# Custom config
201|heimdallr --config /etc/heimdallr/config.toml
202|
203|# Enable QNAME minimization (opt-in, M5.4)
204|# Add to [resolver] in config.toml:
205|#   qname_minimization.enable = true
206|#   qname_minimization.mode    = "strict"   # or "incremental" | "aggressive"
207|#   qname_minimization.max_iterations = 7
208|```
209|
210|---
211|
212|## Configuration
213|
214|Heimdallr reads TOML at `/etc/heimdallr/config.toml` by default. CLI `--config` overrides. Missing keys use defaults.
215|
216|> [!NOTE]
217|> Run `heimdallr --check-config` to validate config without binding ports.
218|
219|### Config reference
220|
221|<details>
222|<summary><strong>Full config.toml reference</strong></summary>
223|
224|```toml
225|# Network
226|listen = ["0.0.0.0:53", "[::]:53"]
227|listen_tls = ["0.0.0.0:853"]       # DoT (M4)
228|listen_quic = ["0.0.0.0:853"]      # DoQ (M4)
229|listen_https = ["0.0.0.0:443"]     # DoH (M4)
230|
231|# Server hostname — used for SOA NS, Let's Encrypt cert auto-detection
232|host = "ns1.example.test."
233|
234|# Zone admin email (SOA RNAME). Default: hostadmin@<host>.
235|# hostadmin = "admin@mynetwork.test"
236|
237|# Zone files directory
238|zones_dir = "/etc/heimdallr/zones"
239|
240|# TLS — auto-detects Let's Encrypt certs from /etc/letsencrypt/live/<host>/
241|[tls]
242|# cert = "/path/to/fullchain.pem"
243|# key = "/path/to/privkey.pem"
244|# letsencrypt_dir = "/etc/letsencrypt/live"
245|
246|# Recursive resolver
247|[resolver]
248|forwarders = ["1.1.1.1:53", "8.8.8.8:53"]
249|forward_protocol = "udp"         # udp|tcp|dot|doh|doq
250|
251|# QNAME minimization (M5.4, RFC 9156) — opt-in. Default enable=false.
252|# When enabled, the forwarder issues one query per label step
253|# (com. -> example.com. -> -> original name) instead of a single
254|# full-QNAME lookup. Falls back to the unminimized query if every
255|# peel step errors. Modes: incremental | aggressive | strict.
256|[resolver.qname_minimization]
257|# enable = false
258|# mode = "strict"
259|# max_iterations = 7
260|
261|qname_randomization = false
262|ecs = false
263|concurrency = 2
264|timeout_ms = 2000
265|
266|# Cache
267|[cache]
268|size = 50000
269|serve_stale = true
270|prefetch = 2
271|# persistent = "/var/lib/heimdallr/cache.bin"
272|
273|# DNSSEC
274|[dnssec]
275|validation = true               # validate upstream responses
276|signing = false                 # global signing flag
277|provider = "ring"               # ring|botan
278|
279|# DNSSEC key management
280|[dnssec_keys]
281|keys_dir = "/var/lib/heimdallr/keys"
282|# trust_anchor = "/var/lib/heimdallr/root-anchors.xml"
283|
284|# Filtering (M6)
285|[filter]
286|blocklists = []
287|allowlists = []
288|regex_blocklist = []
289|# per_client = { "10.0.0.5/32" = { block = false } }
290|cname_cloaking = true
291|rebinding = true
292|
293|# PROXY protocol (M4)
294|[proxy]
295|enable = false
296|allow = []
297|protocol = "v2"                  # v1|v2
298|
299|# API
300|[api]
301|listen = "127.0.0.1:5380"
302|# tls_cert = ""
303|# tls_key = ""
304|
305|# Auth (M7)
306|[auth]
307|# users = [{ name = "admin", password_hash = "$argon2id$..." }]
308|# tokens = []
309|totp = false
310|oidc = false
311|
312|# Logging
313|[log]
314|level = "info"                   # trace|debug|info|warn|error
315|query_log = ""                   # path to query log file
316|format = "json"                  # json|text
317|
318|# DHCP (M8)
319|[dhcp]
320|enable = false
321|# ranges = [{ subnet = "10.0.0.0/24", start = "10.0.0.100", end = "10.0.0.200", router = "10.0.0.1" }]
322|
323|# Clustering (M8)
324|[cluster]
325|enable = false
326|# peers = []
327|
328|# Zones
329|[[zones]]
330|name = "example.test."
331|kind = "primary"                 # primary|secondary|stub|conditional|forwarder
332|file = "example.test.zone"
333|dnssec_signing = true
334|dnssec_algorithm = "ecdsa-p256"  # ecdsa-p256|ecdsa-p384|ed25519|rsa-sha256
335|
336|# NSEC3 configuration (optional)
337|# [zones.nx_proof]
338|# kind = "nsec3"                 # nsec|nsec3
339|# iterations = 0
340|# salt = ""                      # hex-encoded
341|# opt_out = false
342|
343|[[zones]]
344|name = "10.in-addr.arpa."
345|kind = "primary"
346|file = "10.in-addr.arpa.zone"
347|```
348|
349|</details>
350|
351|---
352|
353|## API Reference
354|
355|All endpoints return JSON. API listens on `127.0.0.1:5380` by default.
356|
357|### Health & Info
358|
359|| Method | Endpoint | Description |
360||--------|----------|-------------|
361|| `GET` | `/api/health` | `{"status":"ok","version":"0.4.0-alpha"}` |
362|| `GET` | `/api/info` | Server info — hostname, listen addrs, zones count, DNSSEC, cache, log level |
363|
364|### Zones
365|
366|| Method | Endpoint | Description |
367||--------|----------|-------------|
368|| `GET` | `/api/zones` | List all configured zones |
369|| `GET` | `/api/zones/{name}` | Zone detail (name, kind, file, primaries) |
370|
371|### Records (M3)
372|
373|| Method | Endpoint | Description |
374||--------|----------|-------------|
375|| `GET` | `/api/zones/{name}/records` | List all records in zone |
376|| `GET` | `/api/zones/{name}/records/{type}` | Get records by type |
377|| `POST` | `/api/zones/{name}/records` | Create record (JSON body: `{name, record_type, ttl, data}`) |
378|| `POST` | `/api/zones/{name}/records/delete` | Delete records (JSON body: `{name, record_type}`) |
379|
380|**TLSA record example:**
381|
382|```bash
383|# Add DANE TLSA record
384|curl -X POST http://127.0.0.1:5380/api/zones/example.test./records \
385|  -H 'Content-Type: application/json' \
386|  -d '{"name":"_443._tcp.www","record_type":"TLSA","ttl":3600,"data":"3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"}'
387|```
388|
389|---
390|
391|## Operation
392|
393|### Install
394|
395|```bash
396|sudo ./scripts/install.sh
397|```
398|
399|The install script builds the release binary, creates the `heimdallr` user/group, and installs all files. It detects existing config/zone/systemd files and prompts before overwriting — declined files are placed in `/opt/heimdallr/zones/templates/`.
400|
401|### systemd
402|
403|```bash
404|sudo systemctl disable --now systemd-resolved  # if in use
405|sudo systemctl enable --now heimdallr
406|echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
407|journalctl -u heimdallr -f
408|```
409|
410|> [!IMPORTANT]
411|> These commands disable `systemd-resolved`. Make sure no other service depends on it.
412|
413|### CLI
414|
415|```bash
416|heimdallr --help
417|heimdallr --check-config
418|heimdallr --config /etc/heimdallr/config.toml --listen 127.0.0.1:5353
419|RUST_LOG=heimdallr=debug,quinn=info heimdallr
420|```
421|
422|### Build verification
423|
424|```bash
425|cargo build --release
426|cargo tree | grep -iE "openssl|bssl|aws-lc"   # must be empty
427|cargo audit
428|```
429|
430|---
431|
432|## RFC Coverage
433|
434|### Core wire
435|
436|| RFC | Title | Status |
437||-----|-------|--------|
438|| 1035 + 1034 | DNS base | ✅ M1 — `hickory-proto` |
439|| 6891 | EDNS(0) | ✅ M1 |
440|| 7766 | DNS over TCP (+ pipelining §7) | ✅ M1 |
441|| 8482 | ANY RCODE | ✅ M1 |
442|
443|### DNSSEC
444|
445|| RFC | Title | Status |
446||-----|-------|--------|
447|| 4033–4035 | DNSSEC validation/signing | ✅ M3 — `ring` |
448|| 5155 | NSEC3 | ✅ M3 |
449|| 6698 | DANE TLSA | ✅ M3 — CRUD API |
450|| 8976 | ZONEMD | Deferred to M9 |
451|| 8945 | TSIG | M9 |
452|| 9103 | XFR-over-TLS | M9 |
453|
454|### Encrypted transports
455|
456|| RFC | Title | Status |
457||-----|-------|--------|
458|| 7858 | DoT | ✅ M4 — `rustls:ring` |
459|| 8484 | DoH | ✅ M4 — `hickory h2` |
460|| 9250 | DoQ | ✅ M4 — `quinn:ring` |
461|| — | PROXY protocol v1/v2 | ✅ M4 |
462|| — | API TLS | ✅ M4 — `tokio-rustls:ring` |
463|
464|### Zones & transfers
465|
466|| RFC | Title | Status |
467||-----|-------|--------|
468|| 5936 | AXFR | ✅ M2 |
469|| 1996 | NOTIFY | ✅ M2 |
470|| 9432 | Catalog zones | ✅ M2 |
471|| 2136 | Dynamic Updates | M9 |
472|
473|### Records & behaviors
474|
475|| RFC | Title | Status |
476||-----|-------|--------|
477|| 9156 | QNAME minimization | ✅ **M5.4** — `qname_min.rs` (opt-in) |
478|| 7871 | EDNS Client Subnet | M5 |
479|| 8914 | Extended DNS Errors | ✅ M1 |
480|| 7314 | EDNS EXPIRE | M5 |
481|| 9460 | SVCB/HTTPS | M5 |
482|| 7553 | URI | M5 |
483|| 4255 | SSHFP | ✅ M5.2 |
484|| 6672 | DNAME | M5 |
485|| 6147 | DNS64 | M5 |
486|
487|---
488|
489|## Threat Model
490|
491|Heimdallr is a DNS server — every UDP packet is untrusted, every TCP/TLS/QUIC handshake is attacker-controlled before authentication.
492|
493|### Trusted Computing Base
494|
495|| Metric | Value |
496||--------|-------|
497|| Lines of Rust | ~10k + hickory/quinn/rustls/ring/botan |
498|| External C deps | 0 default (ring asm only); optional libbotan-2 |
499|| OpenSSL | 0 (`cargo tree | grep openssl` empty) |
500|| Config format | TOML + typed serde (fails closed) |
501|| Unsafe code | `#![forbid(unsafe_code)]` |
502|
503|### Attack surface
504|
505|| Surface | Risk | Mitigation |
506||---------|------|------------|
507|| **Packet parsing** (`net/`, `hickory-proto`) | Parser CVEs, label compression loops, RDLENGTH OOM | Rust `forbid(unsafe)`, hickory fuzzed upstream, EDNS bufsize caps |
508|| **Cache poisoning** | TXID/port brute force, Kaminsky, NS glue hijack | Randomized TXID+port, **QNAME minimization (M5.4)**, DNSSEC (M3) |
509|| **Encrypted transports** | rustls/quinn handshake DoS, SNI leak | ring crypto, forward_protocol pinned, PROXY allowlist |
510|| **Zone transfers** | Unauthorized AXFR dump | allow-transfer ACL, ZONEMD (M9) |
511|| **Web API :5380** | Auth bypass, token theft, RBAC bypass | argon2id, HMAC tokens, RBAC, TOTP/OIDC (M7) |
512|| **Configuration** | Tampering | root:heimdallr 0640, path traversal rejection |
513|| **Persistence** | cache.bin tampering | 0600 perms, validated header, symlink-resistant |
514|| **Supply chain** | Dependency compromise | Cargo.lock committed, cargo audit/deny in CI |
515|
516|---
517|
518|## Comparison vs Technitium
519|
520|| Area | Technitium | Heimdallr |
521||------|-----------|-----------|
522|| Core | C# .NET, custom wire | Rust hickory (ring) |
523|| Runtime | GC + libmsquic | no GC, quinn+rustls |
524|| Crypto | C# crypto provider | ring + botan (no OpenSSL) |
525|| Cache | serve stale, prefetch, persistent | ✅ M1/M6 |
526|| DNSSEC | RSA/ECDSA/EdDSA, NSEC+NSEC3 | ✅ M3 via ring + botan |
527|| Encrypted | DoT/DoH/DoQ, PROXY v1/v2 | ✅ M4 |
528|| QNAME min | opt-in (always on by default) | ✅ **M5.4** opt-in (`enable=false` default) |
529|| Records | DANE, SVCB/HTTPS ✅, SSHFP ✅, URI, DNAME, ANAME, APP | ✅ DANE M3 · ✅ SVCB/HTTPS M5.1 · ✅ SSHFP M5.2 |
530|| Zones | Primary/Secondary/Stub/CondFwd + catalog, AXFR/IXFR/NOTIFY | ✅ M2 / M9 |
531|| Filter | AdvancedBlocking, DnsBlockList, BlockPage | M6 |
532|| Forwarding | Latency concurrency | resolver.concurrency + M9 |
533|| DHCP | multi-scope | M8 |
534|| Console | Web dashboard + REST API | axum :5380 M6–M7 |
535|| Auth | RBAC + tokens + TOTP + OIDC | M7 |
536|| Clustering | manage N instances | M8 |
537|| Apps | 27 per-app projects | WASM DnsApp trait |
538|| Bench | 100k req/s | >60k qps target M9 |
539|
540|**License difference:** GPL-3.0 network use is not conveying. OSL-3.0 External Deployment forces hosted modifiers to publish source.
541|
542|---
543|
544|## Performance
545|
546|| Metric | Value | Test |
547||
548||--------|-------|------|
549|| Cache lookup (hit) | <105 ns | criterion, 100 measurements |
550|| Cache lookup (miss) | <5 ns | criterion |
551|| Cache insert (256B) | <120 ns | criterion |
552|| PROXY v1 TCP4 parse | <50 ns | criterion |
553|| PROXY v2 TCP4 parse | <40 ns | criterion |
554|
555|> Benchmarks in `benches/cache_bench.rs`. Target: >60k qps cached on i7-8700 class (M9).
556|
557|---
558|
559|## Lessons from Technitium
560|
561|### What Technitium gets right
562|
563|1. **Zero-config that still shows its work.** Stats + query logs make the network legible. Keep M6 logs+metrics first-class.
564|2. **Apps as the escape hatch.** AdvancedBlocking per-client regex + AdvancedForwarding + DnsBlockList + SplitHorizon mean power users never fork core.
565|3. **Forwarder concurrency over static priority.** Latency-based selection with concurrency is real-world snappy.
566|4. **Encrypted path parity.** DoT/DoH/DoQ as both self-hosted services and forwarder protocols is not optional.
567|
568|### What to design out
569|
570|| Scar | Technitium | Heimdallr |
571||------|-----------|-----------|
572|| libmsquic native dep | `apt install libmsquic` | Pure quinn+rustls — zero native QUIC |
573|| GPL-3.0 hides hosted mods | Forks can run unpublished | OSL-3.0 — hosted keeps copyleft |
574|| C# crypto hides agility | Adding GOST/EdDSA = core rebuild | ring + botan-crypto trait |
575|| Query Logs PostgreSQL split | sqlite/mysql/mssql/pgsql fan-out | sqlite default + single PG exporter |
576|| Monolithic WebServiceApi | dashboard+zones/Logs/settings in one file | axum routed modules |
577|| ANAME/APP proprietary | No import story | M5 ANAME + M9 import |
578|
579|### Tuning defaults
580|
581|- Cache: serve-stale on, prefetch=2
582|- QNAME minimization off by default (opt-in via M5.4 — `enable=true` to activate); 0x20 off (middlebox compat)
583|- Forwarders: concurrency 2, timeout 2s
584|- Observability: query.log json + Prometheus (M6)
585|
586|---
587|
588|## Testing & Quality Gates
589|
590|### Test levels
591|
592|```bash
593|# Unit tests
594|cargo test
595|cargo test -- --nocapture
596|RUST_LOG=debug cargo test core::cache --nocapture
597|
598|# QNAME minimization unit tests (M5.4)
599|cargo test --bin heimdallr qname_min
600|
601|# Property & fuzz
602|cargo fuzz run dns_parse -- -max_total_time=60
603|
604|# Integration (requires ports)
605|cargo test --test integration -- --ignored
606|
607|# DNSSEC validation gate
608|./tests/dnssec-validate.sh
609|
610|# QNAME minimization gate (M5.4)
611|RUST_LOG=heimdallr=debug ./tests/qname-min-validate.sh
612|```
613|
614|### CI quality gates (must all pass)
615|
616|```bash
617|cargo fmt --check
618|cargo clippy -- -D warnings
619|cargo check
620|cargo test
621|cargo audit                # no advisories
622|cargo deny check           # bans ok, licenses ok, sources ok
623|cargo tree | grep -ivE "openssl|bssl|aws-lc"  # must be empty
624|```
625|
626|---
627|
628|## Contributing
629|
630|Rules are short — Heimdallr is DNS, not a web toy.
631|
632|- Open an issue for anything larger than a typo. State intent and affected milestone.
633|- One idea per PR.
634|- `rustfmt` default — do not debate.
635|- Comments only where code cannot speak. Short sentences, ASCII.
636|- No new dependency without an issue. List is intentionally tiny — `tokio`, `hickory-*`, `quinn`+`rustls` (`ring`), `botan`, `axum`, `hyper`, `hyper-util`, `tower`, `tokio-rustls`, `anyhow`, `clap`, `tracing`. Adding `openssl`/`boring`/`aws-lc` requires RFC-style justification.
637|- Commit messages: imperative (`Add QNAME minimization`), not `added`.
638|
639|### Bugs & security
640|
641|- Bugs with repro: issue → exact `cargo`/`dig`/`kdig` commands + `RUST_LOG=debug` output.
642|- Security: [SECURITY.md](SECURITY.md) private channel — never issues.
643|
644|---
645|
646|## Security
647|
648|Heimdallr is a DNS server. Bugs here are network amplifiable, cache-poisonable, and privacy-breaking.
649|
650|- **Report via** GitHub private security advisory, or [SECURITY.md](SECURITY.md) channels.
651|- **In scope:** cache poisoning, memory corruption from crafted packets, API auth bypass, DNSSEC bypass, privilege escalation, supply-chain regression.
652|- **Out of scope:** DoS by flooding `127.0.0.1:53` without amplification/poisoning vector, social engineering, physical access.
653|
654|See [SECURITY.md](SECURITY.md) for full details.
655|
656|---
657|
658|## Branding
659|
660|**Heimdallr** — Old Norse. The god who watches the bridge.
661|
662|- **Name:** `Heimdallr` (capital H, lower r terminal). Binary: `heimdallr`. Service: `heimdallr.service`.
663|- **Mark:** `H` formed from `Hagall` rune + bridge arch, stroke Amber (#f59e0b) on Void Black (#0a0a0a).
664|- **Rules:** Do not use marks to endorse a fork without written permission. Derivative web consoles must replace the loading screen sigil.
665|
666|---
667|
668|## License
669|
670|**Open Software License 3.0** — see [LICENSE](LICENSE).
671|
672|```
673|Copyright (c) 2026 Veridian Zenith
674|```
675|
676|- **Use freely**, including commercially.
677|- **Network use = distribution.** External Deployment (LICENSE §28) means hosted modifiers must publish source under OSL-3.0.
678|- **Derivative works stay OSL-3.0.**
679|- **Keep attribution.** Retain copyright notices. Add "Modified by ... on ..." to changed files.
680|
681|---
682|
683|## Contact
684|
685|- **Email:** [daedaevibin@ik.me](mailto:daedaevibin@ik.me)
686|- **Matrix:** [@daedaevibin:matrix.org](https://matrix.to/@daedaevibin:matrix.org)
687|- **Mastodon:** [@daedaevibin@defcon.social](https://defcon.social/@daedaevibin)
688|- **Discord:** [Veridian Zenith](https://discord.gg/Vprc6XRkRg) (email [daedaevibin@ik.me](mailto:daedaevibin@ik.me) when you join)
689|- **Repo:** [github.com/Veridian-Zenith/Heimdallr](https://github.com/Veridian-Zenith/Heimdallr)
690|
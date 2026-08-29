# Heimdallr Roadmap — Parity Ladder to Technitium

Heimdallr is a from-zero Rust DNS server intended to replace `Technitium DNS Server` (`~/Work/Technitium/DnsServer/` + `TechnitiumLibrary/`, both `GPL-3.0`) as a self-hosted, `OSL-3.0` own product. No Technitium code is copied; implementation is derived from RFCs via `hickory-proto`/`hickory-server` (`ring` crypto, no `OpenSSL`/`BoringSSL`/`aws-lc-rs`, optional `Botan` feature).

Do not start `M(n+1)` before `M(n)` gate passes. Linux-only; Windows support deferred.

## M0 Scaffold — DONE
**Gate:** `cargo check` and `cargo build --release` produce `target/release/heimdallr` with `--help` showing `listen`/`api_listen` (`src/main.rs`), `LICENSE` is `OSL-3.0`, docs tree exists.
**Deliverable:** `Heimdallr/` at `~/Work/VZ/Heimdallr/`, `Cargo.toml` pins `tokio`, `hickory-proto:dnssec-ring`, `hickory-server`, `quinn`+`rustls` with `ring` (`README.md:7`).

## M1 UDP/TCP Recursive + Cache
**Scope:** `hickory-resolver` based recursive resolver, system-resolver bypass (`systemd-resolved` handling like `DnsServer/build.md:72-76`), `EDNS(0)` `RFC 6891`, extended errors `RFC 8914`, cache with TTL, serve-stale stub, prefetch hint.
**Gate:** `dig @127.0.0.1:5353 example.com` returns answer from upstream (Cloudflare `1.1.1.1`/Google `8.8.8.8` configurable), second query served from cache (latency <1ms, hit counter increments), `cargo test` includes cache-fuzz.
**RFCs:** `1035`, `6891`, `7766` (TCP), `8482` (ANY mitigation).

## M2 Authoritative Zones + Transfers
**Scope:** Primary/Secondary/Stub/Conditional Forwarder zones, zone files, `$ORIGIN`/`$TTL`, record types `A/AAAA/CNAME/MX/TXT/SOA/NS/PTR/SRV`, `AXFR`/`IXFR` `RFC 1995` + `NOTIFY` `RFC 1996`, catalog zones `RFC 9432`.
**Gate:** Host two primary zones (`example.test.`, reverse `10.in-addr.arpa`), secondary syncs via `AXFR` from primary, `NOTIFY` triggers sub-second refresh; `cargo test` loads 10k-record zone in <200ms.

## M3 DNSSEC Validation & Signing
**Scope:** Validation for recursive/forwarder with `RSA`/`ECDSA`/`EdDSA`, `NSEC`/`NSEC3`, `root-anchors.xml` analogue (`DnsServer/DnsServerCore/root-anchors.xml`), DANE `TLSA` `RFC 6698`, `ZONEMD` `RFC 8976` for secondary. Signing for hosted zones (`RRSIG`/`DNSKEY`/`DS`). Crypto: `ring` by default, `Botan` optional via `--features botan-crypto` for HSM/agile.
**Gate:** `delv @127.0.0.1` validates `dnssec-analyzer` test zones (valid/bogus/insecure), signed `example.test` passes `ldns-verify-zone`, no `OpenSSL` in `cargo tree`.
**Out of scope yet:** `DoT`/`DoH`/`DoQ`.

## M4 Encrypted Transports
**Scope:** Self-host `DoT` `RFC 7858` (`rustls` `ring`), `DoH` `RFC 8484` with `HTTP/1.1`+`HTTP/2` (`axum`+`h2`), `DoQ` `RFC 9250` (`quinn` `ring` - no `libmsquic` `build.md:38`), `DoH/3` later via `quinn`+`h3`, `PROXY protocol v1/v2` for `UDP`+`TCP`, forwarder routing over `DoT`/`DoH`/`DoQ`.
**Gate:** `kdig -d @127.0.0.1 +tls`, `curl --doh-url https://127.0.0.1/dns-query`, `quic` client query all resolve; Wireshark shows no cleartext for forwarder path; `cargo tree | grep -i openssl` empty.

## M5 Advanced Records & Behaviors
**Scope:** `SVCB`/`HTTPS` `RFC 9460`, `URI` `RFC 7553`, `SSHFP` `RFC 4255`, `DNAME` `RFC 6672`, proprietary `ANAME` (apex CNAME flattening) + `APP` record dispatch, QNAME minimization `RFC 9156`, QNAME case randomization `draft-vixie-dnsext-dns0x20-00`, CNAME cloaking block, `DANE` hash auto-gen from `PEM`, `DNS64` `RFC 6147` (like `Dns64App`), `EDNS Client Subnet` `RFC 7871`, `EDNS EXPIRE` `RFC 7314`.
**Gate:** Each record type round-trips via `dig TYPE`, `ANAME` at apex resolves like `CNAME`, `QNAME` minimization visible in `tcpdump` (single-label upstream), `DNS64` synthesizes `AAAA` for `IPv4-only` host.

## M6 Filtering, Apps & Observability
**Scope:** One-or-more blocklist URLs, `regex` blocklists per-client/subnet (parity `AdvancedBlockingApp`), `DnsBlockListApp` domain+IP lists, `BlockPageApp` HTTP sinkhole, `DNS Rebinding Protection`, `DropRequestsApp`/`NxDomainApp`, latency-based forwarder selection (concurrency), persistent cache save/restore, stats + query logs (like `LogExporterApp`/`QueryLogs*App`), Prometheus metrics, HTTP API parity `DnsServer/APIDOCS.md` + `WebService*.cs` (auth, zones, settings, DHCP, logs).
**Gate:** Blocklist blocks `ads.example.test.`, per-client override allows it for `10.0.0.5/32`; API `GET /api/listBlocked` etc matches Technitium `APIDOCS.md` examples; logs export via `Syslog`/`HTTP`/`File`.

## M7 Administration & Hardening
**Scope:** Web console (`axum`+ static files, dark mode like `DnsServerCore/www`), multi-user RBAC + non-expiring `API tokens`, `TOTP` 2FA (`TechnitiumLibrary.Security.OTP`), `Single Sign-On` `OIDC`, system logging, `EDNS`/ECS toggles, split-horizon/geo via Apps (`SplitHorizonApp`/`Geo*App`), clustering stub.
**Gate:**Console CRUD zones/records without restart, RBAC user `auditor` cannot `POST /api/deleteZone`, `TOTP` required when enabled, `cargo audit` clean.

## M8 Auxiliary Services
**Scope:** Built-in `DHCP Server` (`DnsServerCore/Dhcp/`) multi-scope, HTTP/SOCKS5 proxy routing (incl. `Tor` circuit via `SOCKS5` like `README.md:87`), `Cluster` management of N instances (`DnsServerCore/Cluster/`), Docker `Dockerfile`+`docker-compose.yml` parity, `systemd.service` install (`build.md:63-77` flow but `heimdallr` binary).
**Gate:** DHCP lease issued to `qemu` NIC, DNS+DHCP visible in same console; `HTTP/SOCKS5` proxy routes upstream via `Tor` daemon; clustering shows 2 nodes in console from one browser.

## M9 Full Parity & Migration
**Scope:** Remaining `SupportedRFCs.md` gaps, `Secondary` `XFR-over-TLS` `RFC 9103` + `XFR-over-QUIC` `RFC 9250`, `TSIG` `RFC 8945` for transfers/updates `RFC 2136`, `FilterAaaaApp`/`WeightedRoundRobinApp`/`FailoverApp` with health checks, import `Technitium` zone JSON, bulk `AdvancedForwardingApp` `adguard-upstreams.txt` compat, benchmark `README.md:37` target: >80k qps on `i7-8700` class (`Gigabit` `UDP`).
**Gate:** Import `~/Work/Technitium/DnsServer/` backup `zip` zones, all queries match before/after `diff` of `dig` traces; `perf` bench shows `p95 <8ms` recursive cold, `>60k qps` cached.

## Non-goals
Windows service (`DnsServerWindowsService/`/`SystemTrayApp`/`WindowsSetup/`), `QueryLogsPostgreSqlApp.zip` legacy PostgreSQL shape - fresh `sqlite`/`postgres` plugins instead.

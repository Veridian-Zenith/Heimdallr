# Comparison — Heimdallr vs Technitium

From-zero means know the shape of `Technitium/DnsServer/` but not its bytes. Table maps each `Technitium/README.md:29-92` feature to Heimdallr parity and where the bytes differ.

| Area | Technitium (`~/Work/Technitium`) | Heimdallr (`~/Work/VZ/Heimdallr`) | Parity plan |
|---|---|---|---|
| **Core** | `C#` `.NET 10` `DnsServerCore/` (`hundreds` of `*.cs`) + `TechnitiumLibrary.Net` wire | `Rust` `hickory-proto`+`hickory-server` (`ring`) | `ROADMAP.md:M1-M3` — same RFCs, zero copy |
| **Runtime** | `GC` + `libmsquic` (`build.md:38`) for `DoQ`/`H3` | `no GC`, `quinn`+`rustls` `ring` (`README.md:7`) | no native `msquic` |
| **Crypto** | `TechnitiumLibrary.Security.Cryptography` (`PEMFormat.cs`, `CertificateStore.cs`, `Phe`) | `ring` default, `botan` opt (`Cargo.toml:botan-crypto`) | no `OpenSSL`/`BoringSSL`/`aws-lc` default |
| **Cache** | `serve stale`, `prefetch`, `auto-prefetch`, persistent `cache.bin` | `core/cache/` `M1`/`M6` | hit-for-hit |
| **DNSSEC** | `RSA`/`ECDSA`/`EdDSA`, `NSEC`+`NSEC3`, `root-anchors.xml` | same via `ring` (`dnssec-ring`) + `botan` alt | `M3` gate validates `delv` |
| **Enc** | `DoT` `7858`, `DoH` `8484` `H/1.1`/`2`/`3`, `DoQ` `9250`, `PROXY v1/v2` | same (`net/tls|quic|doh|proxy`) | `M4` `kdig`/`curl --doh`/`quic` |
| **Records** | `DANE`, `SVCB`/`HTTPS`, `URI`, `SSHFP`, `DNAME`, `ANAME` flattening, `APP` | same `M5` via `hickory`+`ANAME` glue + `WASM` `APP` | CLI parity |
| **Zones** | `Primary`/`Secondary`/`Stub`/`CondFwd`+catalog `9432`, `AXFR`/`IXFR`/`NOTIFY`, `ZONEMD` `8976` | same `M2`/`M9` | import `Technitium` `zip` in `M9` |
| **Transfers** | `TSIG` `8945`, `XFR-over-TLS` `9103`+`QUIC` `9250` | same `M9` | `ldns` interop |
| **Filter** | `AdvancedBlockingApp` `regex` per-client, `DnsBlockListApp`, `BlockPageApp`, `DNRP`, `FilterAaaa` | `core/filter` `M6` | per-client `10.0.0.5/32` gate |
| **Forwarding** | Latency `concurrency` + `AdvancedForwardingApp` `adguard-upstreams.txt` | `resolver.concurrency` + `M9` import of `adguard-upstreams.txt` | `M6`/`M9` |
| **Behaviors** | `QNAME min` `9156`, `0x20` randomization, `CNAME` cloaking, `ECS` `7871`, `EDE` `8914`, `DNS64` `6147` | same `M5` | `tcpdump` visible |
| **DHCP** | `DnsServerCore/Dhcp/` multi-scope | `dhcp/` `M8` | lease to `qemu` NIC gate |
| **Proxy** | `HTTP`+`SOCKS5` via `Tor` | same via `tokio` `socks` + `Tor` circuit | `SOCKS5` upstream |
| **Console** | `DnsServerCore/www` + `DnsWebService*.cs` `APIDOCS.md` `:5380` | `axum` `:5380` `API` `M6-M7` | `POST /api/*` JSON shapes match |
| **Auth** | Multi-user `RBAC` + non-expiring `API token` + `TOTP` `OTP/Authenticator.cs` + `OIDC` | `api/auth` `argon2id`+`TOTP`+`OIDC` | `M7` `Voix` `PAM` not needed |
| **Clustering** | `DnsServerCore/Cluster/` manage N instances | `cluster/` `M8` | 2-node `console` gate |
| **Observability** | Stats + query `sqlite`/`mysql`/`pgsql` (`QueryLogs*App`) + `LogExporterApp` | `query.log` `JSON` + `sqlite`, `Prometheus` | `M6` `Syslog`/`HTTP`/`File` |
| **Apps** | 27 `DnsServer/Apps/*/` `dnsApp.config` `C#` per-app `csproj` | `apps/` `WASM` `sandboxed` `DnsApp` trait (never `C#` direct) | `apps2.json` compat later |
| **Packaging** | `DnsServerWindowsSetup` `Inno Setup`, `DnsServerApp/install.sh`+`systemd.service`, `Dockerfile` | `systemd`+`Docker` only (Windows deferred) | `docs/operation.md` |
| **Bench** | `High performance async IO` `100k req/s` `i7-8700` `ROADMAP` `i7-8700` | `>60k qps` cached `M9` `Flamethrower` | `tokio` batched `recvmmsg` |

## Non-goals vs Technitium

- No `DnsServerWindowsService`/`SystemTrayApp`/`WindowsSetup` — deferred per task (`refrain windows support`).
- No direct `Query Logs (PostgreSQL).zip` shape — fresh `sqlite` + `postgres` plugin with same export API (`docs/operation.md:Observability`).

## License difference (core motive)

`GPL-3.0` (`LICENSE` `Technitium`) network use is not conveying. `Heimdallr` `OSL-3.0` `External Deployment` (`docs/license.md:LICENSE:28`) forces any hosted modifier to publish source — the `productivity push` the prompt asks for.

## Branding difference

`Technitium` `img/logo.png` + `DnsServerApp/logo2.ico` vs `Heimdallr` `Hagall` sigil `Amber`/`Void Black` `docs/branding.md`.

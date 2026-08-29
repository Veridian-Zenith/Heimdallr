# Lessons from Technitium

Heimdallr learns from living on `Technitium DNS Server` (`~/Work/Technitium/DnsServer/` `21M` + `TechnitiumLibrary/` `5.7M`, `README.md:12-26` self-host value). `Verdandi/docs/lessons-from-host.md` teaches tuning a host; this teaches not porting a host.

## What Technitium gets right (keep)

1. **Zero-config that still shows its work.** `Works out-of-the-box with zero config` `README.md:32` but `Stats` + `Query logs` make the network legible. Keep `M6` logs+metrics first-class, not an after-page.
2. **Apps as the escape hatch.** `AdvancedBlockingApp` per-client `regex` + `AdvancedForwardingApp` `adguard-upstreams.txt` + `DnsBlockListApp` + `SplitHorizonApp` mean power users never fork core. `docs/architecture.md:apps/` `WASM` must be equally wide.
3. **Forwarder concurrency over static priority.** Latency-based selection with concurrency for recursive+forwarders (`README.md:42`) explains real-world snappiness.
4. **Encrypted path parity.** `DoT`/`DoH`/`DoQ` as both self-hosted services and forwarder protocols (`README.md:37-43`) is not optional for privacy `README.md:16`.

## What to design out from day one

| Host scar | Technitium shape | Heimdallr encoding |
|---|---|---|
| `libmsquic` is a second packaging truth (`build.md:38-41` `sudo apt install libmsquic -y`, `skip if you don't plan to use QUIC`) | Two codepaths (`--skip` branch) | Pure `quinn`+`rustls` `ring` — `cargo tree` `openssl`-free (`README.md:7`). Zero `native QUIC` to install. |
| `GPL-3.0` hides hosted mods (network != convey) | Forks can run unpublished | `OSL-3.0` `External Deployment` (`docs/license.md`) — hosted keeps copyleft. |
| `C#` `TechnitiumLibrary.Security.*` hides agility | Adding `GOST`/`EdDSA` is core rebuild | `ring` default + `botan-crypto` feature `Cargo.toml:19` — agility behind a `trait`, not a fork. |
| `Query Logs (PostgreSQL).zip` + `QueryLogs*App` per-engine plugins | Dialect split (`sqlite`/`mysql`/`mssql`/`pgsql`) | `sqlite` default + single `postgres` exporter (`ROADMAP.md:M6` `LogExporterApp` parity) — no engine fan-out. |
| Windows service as first-class install | `DnsServerWindowsSetup` `Inno Setup` (`build.md:4-11`) + `DnsServerWindowsService` | Linux `systemd`+`Docker` only per task `refrain windows support`; keep cross-build honest (`docs/operation.md:systemd` `AmbientCapabilities=CAP_NET_BIND_SERVICE`). |
| Monolithic `DnsServerCore/WebService*.cs` | `WebServiceApi.cs` covers `dashboard`+`zones`+`logs`+`settings`+`Dhcp` | `api/` routed `axum` modules (`docs/architecture.md:Module map`) — same `APIDOCS.md` shapes, but boundary-clean for extraction (`Verdandi/docs/architecture.md:25` contract). |
| `ANAME`/`APP` proprietary with no import story | `README.md:56-57` | `M5` `ANAME` flattening parity + `M9` import of `Technitium` `zip` zones (`ROADMAP.md:M9` gate `diff` of `dig` traces). |

## Tuning defaults Heimdallr ships pre-scarred

- Caching: `serve-stale` on, `prefetch=2` (`Galdr`-style `zstd`-default compression vibe — smart default, opt-out).
- `QNAME` minimization on by default (`RFC 9156`), `0x20` off (middlebox compat) — like `Verdandi` `split_lock_detect` default-on with escape hatch (`Verdandi/docs/lessons-from-host.md:49`).
- Forwarders: concurrency `2`, timeout `2s` (`docs/configuration.md:resolver.concurrency`), `byte-based` caps not ratio (same lesson as `dirty_bytes` `Verdandi/docs/lessons-from-host.md:15`).
- Observability budgets: `query.log` `json` + `Prometheus` `metrics`, generation-counter cache kill (`O(1)` metadata bump `Verdandi/docs/lessons-from-host.md:67` analogy) — dropping `cache.bin` scope is instant.

## Migration path (your machine)

You run Technitium now — `Heimdallr` earns trust by `M9` `ROADMAP.md:M9` gate: import `~/Work/Technitium/DnsServer/` backup zones, `diff` `dig` traces, then `DoH`/`DoQ` forwarder jobs flip. Do not disable `systemd-resolved` kill `build.md:71-72` until `M1` bench clears `>10k qps` locally.

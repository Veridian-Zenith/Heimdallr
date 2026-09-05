# Heimdallr M7 — Apps, Auth, and Web Console

**Milestone:** M7 (starts at `v0.7.0-alpha`; M6 complete at `v0.6.5-alpha`)
**Branch target:** `main`
**Author:** Solo maintainer workflow (`Veridian-Zenith`)

This milestone owns the `Apps/` integration (`dnsApp.config` replacement), auth (`auth` module: RBAC + TOTP + OIDC), split-horizon/geo per-client routing, runtime toggle endpoint (`PUT /api/rec/options`), and the web console (`axum` + static + basic RBAC). All original code — no Technitium derivation.

---

## 1. M7.1 — Apps (Split-Horizon / Geo / Per-App Routing)

**Status:** Planned (stub trait `DnsApp` exists; registry empty)
**File targets:** `src/apps/mod.rs`, `net/mod.rs` (pass registry to `CacheForwardAuthority`), `core/filter/mod.rs` (per-app ACL override hook)

Goals:
- Load `dnsApp` instances from `config/apps/` (JSON / TOML registry — no `C#` `.csproj` reference).
- `AppRegistry` holds `Vec<Box<dyn DnsApp>>`; `load_app_registry(config)` parses `apps_dir`.
- Per-app `handle_query` overrides the global filter/blocklist: split-horizon (LAN clients see internal zone records) and geo (IP-based routing to nearest zone).
- Integration: `CacheForwardAuthority::new` takes optional `Arc<AppRegistry>`; lookup checks registry before upstream forward (M5.5 follow-up).

Success criteria:
- `AppRegistry::new()` loads apps from `config/apps/*.json` (or TOML).
- `dns_app::DnsApp` trait has `name()`, `handle_query()`, `region_for_client()`.
- Unit test: registry loads 2 apps, lookup returns different records per client subnet.
- No Technitium `Apps/apps2.json` reference in source; only original `dnsApp.config`-style JSON.

# Heimdallr M7 — Administration & Hardening

**Milestone:** M7 (starts at `v0.7.0-alpha`; M6 complete at `v0.6.5-alpha`)
**Branch target:** `main`
**Author:** Solo maintainer workflow (`Veridian-Zenith`)

This milestone adds config persistence, real authentication, runtime config hot-reload, and the Apps system. All original code — no Technitium derivation.

---

## Sub-milestone ordering

Work proceeds in numerical order. Each step builds on the previous.

| # | Name | Status | Depends on |
|---|------|--------|------------|
| **M7.1** | Config persistence + RBAC enforcement | **Next** | — |
| **M7.2** | Auth layer (argon2id, tokens, TOTP) | Planned | M7.1 |
| **M7.3** | Runtime toggle (in-memory config update) | Planned | M7.2 |
| **M7.4** | Apps (split-horizon, geo routing) | Planned (stub exists) | — (independent) |

---

## 1. M7.1 — Config Persistence + RBAC Enforcement

**Status:** Next (stub config write exists in `PUT /api/rec/options`)
**File targets:** `src/config/mod.rs` (Config::save), `src/api/mod.rs` (RBAC gate), `src/auth/mod.rs` (remove stubs)

### Goals

- `Config::save(path)` — serialize self to TOML and write to disk. Used by runtime toggle endpoint to persist changes across restarts.
- Wire real RBAC gate on `PUT /api/rec/options`: require `dns_admin` role via session token (HMAC-signed, validated from `Authorization` header).
- Remove blanket `#[allow(unused, dead_code, ...)]` from `src/auth/mod.rs` — the module now has real functionality.
- Config persistence path: track where config was loaded from (`Config.source_path`), write back to same path on save.

### Design

```
Config::save(&self, path: impl AsRef<Path>) -> Result<()>
```

- Serializes `self` via `toml::to_string_pretty`
- Writes atomically: write to `{path}.tmp`, rename to `{path}` (prevents corrupt partial writes)
- Creates parent directories if missing
- Returns `Result<()>` — caller logs errors, never crashes

RBAC gate:

- `Authorization: Bearer <token>` header
- Token is HMAC-SHA256 of `(user, expires, nonce)` signed with a key derived from `auth.token_secret`
- `AuthConfig.token_secret` — auto-generated on first start, persisted in config
- `AuthSession::from_token(token, secret)` — validates and returns session
- If auth is not configured (no users, no tokens), allow all (backwards compatible)

### Success criteria

- `Config::load(path)` → `Config` → `config.save(path)` round-trips cleanly
- `PUT /api/rec/options` returns 401 when auth configured but no token provided
- `PUT /api/rec/options` returns 403 when token valid but `dns_admin` role missing
- `PUT /api/rec/options` succeeds when `dns_admin` role present
- `cargo test` passes, `clippy -D` clean

---

## 2. M7.2 — Auth Layer

**Status:** Planned
**File targets:** `src/auth/mod.rs`, `src/api/mod.rs` (session middleware)

### Goals

- `argon2id` password hashing for `AuthUser` (config stores hashes, not plaintext)
- HMAC session tokens: `AuthSession::new(user, secret) → token`, `AuthSession::from_token(token, secret) → Option<AuthSession>`
- TOTP 2FA: `totp-rs` or `hmac` crate for TOTP generation/verification
- Session middleware for axum: extract `Authorization` header, validate token, inject `AuthState` into request extensions

### Success criteria

- `AuthUser` stores `argon2id` hash; `verify_password(plain, hash) -> bool`
- `AuthSession::new` produces a valid HMAC token
- `AuthSession::from_token` validates and returns session or None
- TOTP secret generation + QR code URL for authenticator apps
- `cargo test` passes

---

## 3. M7.3 — Runtime Toggle

**Status:** Planned
**File targets:** `src/api/mod.rs`, `src/config/mod.rs`

### Goals

- `PUT /api/rec/options` actually updates the running config in-memory
- Changes take effect immediately (qname minimization, ECS, DNS64 settings)
- Persist to disk via `Config::save()` (M7.1) so changes survive restart
- GET endpoint returns current runtime values

### Success criteria

- `GET /api/rec/options` returns current qname_min/ecs/dns64 values
- `PUT /api/rec/options` updates in-memory config and persists to disk
- After PUT, next query uses updated settings
- `cargo test` passes

---

## 4. M7.4 — Apps (Split-Horizon / Geo Routing)

**Status:** Planned (stub trait `DnsApp` exists; registry empty)
**File targets:** `src/apps/mod.rs`, `net/mod.rs`, `core/filter/mod.rs`

### Goals

- Load `dnsApp` instances from `config/apps/` (JSON / TOML registry)
- `AppRegistry` holds `Vec<Box<dyn DnsApp>>`; `load_app_registry(config)` parses `apps_dir`
- Per-app `handle_query` overrides global filter/blocklist: split-horizon (LAN clients see internal zone records) and geo (IP-based routing to nearest zone)
- Integration: `CacheForwardAuthority::new` takes optional `Arc<AppRegistry>`

### Success criteria

- `AppRegistry::new()` loads apps from `config/apps/*.json` (or TOML)
- `DnsApp` trait has `name()`, `handle_query()`, `region_for_client()`
- Unit test: registry loads 2 apps, lookup returns different records per client subnet
- No Technitium `Apps/apps2.json` reference in source

# Heimdallr

[![CI](https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml/badge.svg)](https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/ci.yml)
[![Release](https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml/badge.svg)](https://github.com/Veridian-Zenith/Heimdallr/actions/workflows/release.yml)

**Watcher at the Bifrost — privacy & security DNS server.**

From-zero Rust DNS server built to replace Technitium DNS Server long-term. No code copied — wire format implemented from RFCs via `hickory-proto`/`hickory-server`.

Pure `ring` + `quinn`/`rustls` for DoQ/DoH — no `libmsquic`, no `OpenSSL`/`BoringSSL`/`aws-lc-rs`. Optional `Botan` for HSM/agile crypto.

## Status

`0.2.0-alpha` — M0 scaffold + M1 partial. See `ROADMAP.md` for the parity ladder.

## Quick start

```bash
cargo run -- --help
cargo build --release  # -> target/release/heimdallr
```

## Docs

| Doc | Purpose |
|---|---|
| `ROADMAP.md` | M0–M9 parity ladder |
| `SECURITY.md` | Advisory policy |
| `CONTRIBUTING.md` | CI gates (fmt/clippy/audit/deny + OpenSSL ban) |
| `docs/architecture.md` | net→core→api, crypto decision |
| `docs/rfcs.md` | RFC coverage |
| `docs/configuration.md` | config.toml reference |
| `docs/operation.md` | systemd install |
| `docs/threat-model.md` | TCB framing |
| `docs/testing.md` | Unit/fuzz/integration gates |
| `docs/comparison.md` | vs Technitium |
| `docs/branding.md` | Naming and marks |
| `docs/license.md` | OSL-3.0 |
| `docs/lessons-from-technitium.md` | Design decisions from Technitium experience |

## License

`OSL-3.0` — see `LICENSE`. Network use counts as distribution; source must be offered. `Copyright (c) 2026 Veridian Zenith`.

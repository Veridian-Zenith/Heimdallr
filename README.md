# Heimdallr

**Watcher at the Bifrost - privacy & security DNS server.**

From-zero Rust recreation inspired by `Technitium DNS Server` (`DnsServer/` + `TechnitiumLibrary/` `GPL-3.0` clones at `~/Work/Technitium`), built to replace it long-term as an `OSL-3.0` own product. No code copied - wire format implemented from RFCs via `hickory-proto`.

> Single language: Rust. Pure `ring` + `quinn`/`rustls` for `DoQ/DoH`+`HTTP/3` - no `libmsquic` required (`DnsServer/build.md:38`), no `OpenSSL`/`BoringSSL`/`aws-lc-rs`. DNSSEC via `hickory-proto:dnssec-ring` (`ring`), optional `Botan` crate (`--features botan-crypto`) for HSM/custom.

## Status
`0.1.0` scaffold. See `ROADMAP.md` for parity ladder to `Technitium README.md:29-92`.

## Quick start
```bash
cargo run -- --help
cargo build --release # -> target/release/heimdallr
```

## Structure (mirrors `Galdr` `Cargo.toml:1-11`)
```
Heimdallr/
├── Cargo.toml
├── LICENSE # OSL-3.0 like Galdr/Verdandi/Voix
├── README.md
└── src/main.rs
```

## Docs

Thorough docs at `docs/` (index `docs/README.md`):

| Doc | Purpose |
|---|---|
| `ROADMAP.md` | `M0-M9` parity ladder |
| `SECURITY.md` | advisories |
| `CONTRIBUTING.md` | gates (`fmt`/`clippy`/`audit`/`deny` + `openssl` ban) |
| `docs/architecture.md` | `net`→`core`→`api`, crypto decision |
| `docs/rfcs.md` | RFC coverage vs `SupportedRFCs.md` |
| `docs/configuration.md` | `heimdallr.toml` ref |
| `docs/operation.md` | `systemd`+`Docker` |
| `docs/threat-model.md` | `Voix/THREATS.md` TCB |
| `docs/testing.md` | `libFuzzer`+`dig` gates |
| `docs/comparison.md` | vs Technitium table |
| `docs/branding.md` | `Hagall` sigil, tokens |
| `docs/license.md` | `OSL-3.0` `External Deployment` |
| `docs/lessons-from-technitium.md` | scars not ported |

## License & Branding

`OSL-3.0` — see `LICENSE` (same as `Galdr/LICENSE`, `Verdandi/LICENSE:47`, `Voix/README.md:265`) and `docs/license.md`. `External Deployment` (`LICENSE:28`) requires network users be offered source. Branding rules in `docs/branding.md` — retain `Copyright (c) 2026 Veridian Zenith` + `Licensed under OSL-3.0` adjacent, no use of `Veridian Zenith`/`Heimdallr` marks to endorse forks without permission (`LICENSE:25`, `docs/branding.md:Usage`).

New assets must be own (`docs/branding.md` forbids reusing `DnsServerCore/www`/`logo2.ico`).

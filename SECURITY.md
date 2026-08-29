# Security Policy

Heimdallr is a DNS server. Bugs here are not just crashes — they are network amplifiable, cache-poisonable, and privacy-breaking. Reports are treated accordingly.

## How to report

Use GitHub's private security advisory (Security tab → Report a vulnerability) for `Veridian-Zenith/Heimdallr`. If you cannot, email `daedaevibin@ik.me` (see `vzdev.indevs.in` contact) and ask for a private channel. Do not open a public issue for anything exploitable.

Do not disclose externally until a fix is released.

## What to expect

- Confirmation within 48 hours.
- Fix or explicit wont-fix rationale before any disclosure.
- Credit if requested.

## In scope

- Cache poisoning / response forgery reachable over UDP/TCP/TLS/QUIC/HTTPS.
- Memory corruption or panic reachable from a crafted DNS packet (any transport).
- Authentication bypass on `API` (`:5380`) — `API tokens`/`TOTP`/`OIDC` (`ROADMAP.md:M7`).
- Zone-transfer/TSIG bypass, unauthorized `AXFR`/`IXFR`/`NOTIFY` acceptance.
- DNSSEC validation bypass (bogus marked secure) or signing key exfiltration.
- Privilege escalation from the `heimdallr` service user.
- Supply-chain: `cargo.lock`/`cargo audit` regression, `ring`/`quinn`/`rustls`/`hickory` advisory.

## Out of scope

- `DoS` by flooding `127.0.0.1:53` without amplification/poisoning vector (rate-limit is best-effort).
- Social engineering, physical access.
- `Botan` HSM integration when `--features botan-crypto` is off (pure `ring` path is in scope).

## Hardening posture

- No `OpenSSL`/`BoringSSL`/`aws-lc-rs` in default build (`Cargo.toml` pins `ring` + `quinn` `ring` + `rustls` `ring`; `cargo tree | grep -i openssl` must be empty).
- Pure `Rust`, `#![forbid(unsafe_code)]` except in declared `afl`/`ffi` shims for `Botan` (`botan-sys`).
- `release` profile: `lto=true`, `strip=symbols`, `panic=abort` (`Cargo.toml:profile.release` mirrors `Galdr/Cargo.toml:18-23`).
- Future: `RUSTFLAGS="-D warnings"` gate, `cargo audit`/`cargo deny` in CI, `libFuzzer` for `hickory-proto` parsing.

## Disclosure

Once fixed, advisories are published under `GHSA` and `SECURITY.md` is updated with affected versions. `OSL-3.0` requires patched source disclosure for any hosted deployment.

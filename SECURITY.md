# Security Policy

Heimdallr is a DNS server. Bugs here are not just crashes — they are network amplifiable, cache-poisonable, and privacy-breaking. Reports are treated accordingly.

## How to report

Use GitHub's private security advisory (Security tab → Report a vulnerability) for `Veridian-Zenith/Heimdallr`. If you cannot, reach out via:

- **Email:** [daedaevibin@ik.me](mailto:daedaevibin@ik.me)
- **Matrix:** [@daedaevibin:matrix.org](https://matrix.to/@daedaevibin:matrix.org#/@daedaevibin:matrix.org)
- **Mastodon:** [@daedaevibin@defcon.social](https://defcon.social/@daedaevibin)
- **Discord:** [Veridian Zenith](https://discord.gg/Vprc6XRkRg) (message [daedaevibin@ik.me](mailto:daedaevibin@ik.me) when you send a join request so I see it)

Do not open a public issue for anything exploitable. Do not disclose externally until a fix is released.

## What to expect

- Confirmation within 48 hours.
- Fix or explicit wont-fix rationale before any disclosure.
- Credit if requested.

## In scope

- Cache poisoning / response forgery reachable over UDP/TCP/TLS/QUIC/HTTPS.
- Memory corruption or panic reachable from a crafted DNS packet (any transport).
- Authentication bypass on API (`:5380`).
- Zone-transfer/TSIG bypass, unauthorized AXFR/IXFR/NOTIFY acceptance.
- DNSSEC validation bypass (bogus marked secure) or signing key exfiltration.
- Privilege escalation from the `heimdallr` service user.
- Supply-chain: `Cargo.lock`/`cargo audit` regression, `ring`/`quinn`/`rustls`/`hickory` advisory.

## Out of scope

- DoS by flooding `127.0.0.1:53` without amplification/poisoning vector.
- Social engineering, physical access.
- `Botan` HSM integration when `--features botan-crypto` is off.

## Hardening posture

- No `OpenSSL`/`BoringSSL`/`aws-lc-rs` in default build.
- Pure Rust, `#![forbid(unsafe_code)]`.
- `release` profile: `lto=true`, `strip=symbols`, `panic=abort`.
- CI: `cargo audit`/`cargo deny`, `libFuzzer` for packet parsing.

## Disclosure

Once fixed, advisories are published under `GHSA` and [SECURITY.md](SECURITY.md) is updated with affected versions. `OSL-3.0` requires patched source disclosure for any hosted deployment.

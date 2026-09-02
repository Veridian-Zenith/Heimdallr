# Third-Party Licenses

Heimdallr is licensed under the [Open Software License version 3.0](LICENSE)
(OSL-3.0). Per Section 3 of the OSL-3.0, this document preserves
attribution for the third-party components Heimdallr links against
or distributes in object form.

For authoritative license texts, see each crate's own `LICENSE` file
on <https://crates.io> or its source repository.

## Allowed licenses

[`deny.toml`](deny.toml) restricts transitive dependencies to:

`OSL-3.0`, `MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `BSL-1.0`

Any other license will fail `cargo deny check` in CI.

## Crypto stack

Heimdallr's default build is `ring`-based (`hickory-proto`'s `ring`
feature + `rustls`'s `ring` crypto provider). The optional
`botan-crypto` feature pulls in the `botan` crate (BSD-2-Clause) for
an alternative TLS backend used by DoT/DoH/DoQ.

CI explicitly bans `openssl-sys`, `boringssl-sys`, and `aws-lc-sys` in
the default build via a `cargo tree | grep` step in
[`ci.yml`](.github/workflows/ci.yml) — see the `OpenSSL ban` job step.

## Direct dependencies (grouped)

Full crate names, versions, and license fields live in
[`Cargo.toml`](Cargo.toml) and the resolved set in
[`Cargo.lock`](Cargo.lock). The categories below summarise the
direct-dependency surface; every entry links to its upstream source.

### DNS protocol (`hickory-dns`)

- `hickory-proto`, `hickory-server`, `hickory-resolver`, `hickory-net` 0.26.1
  — MIT OR Apache-2.0 — <https://github.com/hickory-dns/hickory-dns>

### Async runtime

- `tokio` 1 — MIT — <https://github.com/tokio-rs/tokio>

### Cryptography & TLS

- `ring` 0.17 — multi-license (see upstream)
  — <https://github.com/briansmith/ring>
- `rustls` 0.23, `tokio-rustls` 0.26, `rcgen` 0.14
  — Apache-2.0 OR ISC OR MIT — <https://github.com/rustls/rustls>
- `quinn` 0.11 — MIT OR Apache-2.0 — <https://github.com/quinn-rs/quinn>
- `botan` 0.14 (optional, default feature) — BSD-2-Clause
  — <https://github.com/randombit/botan-rs>

### HTTP server & API

- `axum` 0.8 — MIT — <https://github.com/tokio-rs/axum>
- `hyper` 1, `hyper-util` 0.1 — MIT — <https://github.com/hyperium/hyper>

### Configuration & observability

- `clap` 4 — MIT OR Apache-2.0 — <https://github.com/clap-rs/clap>
- `serde` 1, `toml` 1.1.4 — MIT OR Apache-2.0 — <https://github.com/serde-rs/serde>
- `tracing` 0.1, `tracing-subscriber` 0.3 — MIT
  — <https://github.com/tokio-rs/tracing>

### Benchmarking (dev-only)

- `criterion` 0.8 — Apache-2.0 OR MIT — <https://github.com/bheisler/criterion.rs>

## Generation

For a machine-generated dependency manifest (recommended when the
dependency tree grows past ~30 direct deps), install
[`cargo-about`](https://github.com/EmbarkStudios/cargo-about) and run
`cargo about generate about.hbs`.

## See also

- [`LICENSE`](LICENSE) — full text of the Open Software License 3.0
- [`README.md` § License](README.md#license) — project license summary
- [`deny.toml`](deny.toml) — `cargo-deny` allowlist
- [`SECURITY.md`](SECURITY.md) — security policy

# Contributing

Rules are short — Heimdallr is DNS, not a web toy.

## Before code

- Open an issue for anything larger than a typo. State intent and affected [ROADMAP.md](ROADMAP.md) milestone.
- One idea per PR.
- Read [docs/architecture.md](docs/architecture.md).

## Must pass before opening PR

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
cargo audit                # no advisories (hickory-proto 0.25 advisories RUSTSEC-2026-0118, -0119 are ignored — fixed in 0.26 upgrade, see ROADMAP)
cargo deny check
cargo tree | grep -ivE "openssl|bssl|aws-lc"  # must be empty
```

If you touch boot/service behavior, paste `systemctl status heimdallr` and `journalctl -u heimdallr -n 20`.

## Style

- `rustfmt` default — do not debate.
- Comments only where code cannot speak. Short sentences, ASCII.
- No new dependency without an issue. List is intentionally tiny — `tokio`, `hickory-*`, `quinn`+`rustls` (`ring`), `axum`, `anyhow`/`thiserror`, `clap`, `tracing`. Adding `openssl`/`boring`/`aws-lc` requires RFC-style justification and is rejected for default builds.
- Commit messages: imperative (`Add QNAME minimization`), not `added`.

## Reporting

- Bugs with repro: issue → exact `cargo`/`dig`/`kdig` commands + `RUST_LOG=debug` output.
- Security: [SECURITY.md](SECURITY.md) private channel — never issues.
- Contact: [daedaevibin@ik.me](mailto:daedaevibin@ik.me) | [@daedaevibin:matrix.org](https://matrix.to/@daedaevibin:matrix.org#/@daedaevibin:matrix.org) | [Discord](https://discord.gg/Vprc6XRkRg) (email me when you join so I see it)

## Licensing

By contributing you agree your work is under `OSL-3.0` ([LICENSE](LICENSE)).

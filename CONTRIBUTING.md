# Contributing

Thanks for interest. Rules are short — `Heimdallr` is DNS, not a web toy.

## Before code

- Open an issue for anything larger than a typo. State intent, affected `ROADMAP.md` milestone, and whether it touches packet parsing (fuzz target needed).
- One idea per PR. If it fixes `DoQ` and renames 3 modules, it is two PRs.
- Read `docs/architecture.md` — two rules are enforced in review, not style:
  - modules only talk through `src/<crate>/public` or `pub(crate)` boundaries; no `super::*` across milestones.
  - any decision that changes a `Verdandi/docs/architecture.md:50` style log entry gets a dated line in `docs/architecture.md#decisions-log`.

## Must pass before opening PR

```sh
cargo fmt --check          # rustfmt gate (like Galdr/Verdandi clang-format)
cargo clippy -- -D warnings
cargo check
cargo test                 # must pass; new parser code needs proptest/fuzz case
cargo audit                # no advisories
cargo deny check           # no banned crates (OpenSSL/BoringSSL banned in default)
cargo tree | grep -ivE "openssl|bssl|aws-lc" # empty
```

If you touch boot/service behavior (`docs/operation.md:systemd`/`Dockerfile`), paste `systemctl status heimdallr` and `journalctl -u heimdallr -n 20`.

## Style

- `rustfmt` default — do not debate.
- Comments only where code cannot speak. Short sentences, ASCII.
- No new dependency without an issue. List is intentionally tiny — `tokio`, `hickory-*`, `quinn`+`rustls` (`ring`), `axum`, `anyhow`/`thiserror`, `clap`, `tracing`. Adding `openssl`/`boring`/`aws-lc` requires RFC-style justification and is rejected for default builds; use `botan-crypto` feature instead.
- Commit messages: imperative (`Add QNAME minimization`), not `added`.

## Reporting

- Bugs with repro: issue → exact `cargo`/`dig`/`kdig` commands + `RUST_LOG=debug` output.
- Security: `SECURITY.md` private channel — never issues.

## Licensing

By contributing you agree your work is under `OSL-3.0` (`LICENSE`, same as `Galdr/LICENSE`, `Verdandi/LICENSE`, `Voix/LICENSE`). That is the whole agreement — publication/network use stays `OSL-3.0` per `LICENSE:27-28` External Deployment.

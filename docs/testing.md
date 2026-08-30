# Testing

Heimdallr is 53/udp trust boundary — tests are gates, not suggestions.

## Levels

### 1. Unit (`cargo test`)

```bash
cargo test
cargo test -- --nocapture
RUST_LOG=debug cargo test core::cache --nocapture
```

### 2. Property & fuzz

```bash
cargo fuzz run dns_parse -- -max_total_time=60
```

- `libFuzzer` target feeds raw UDP bytes to `hickory-proto` — no panic on crafted inputs.
- Planned: QUIC `ClientHello` tampering corpus.

### 3. Integration (requires ports)

```bash
cargo test --test integration -- --ignored
```

- Spawns heimdallr on unprivileged ports, digs it.
- `Flamethrower`/`dnsperf` for bench target.

### 4. Interop

- `ldns-verify-zone` for M3 signed zones.
- `delv @127.0.0.1` for validation.

## Quality gates (CI — `CONTRIBUTING.md`)

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo audit
cargo deny check
cargo tree | grep -iE "openssl|bssl|aws-lc" && exit 1
cargo test
```

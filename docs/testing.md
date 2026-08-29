# Testing

Heimdallr is `53/udp` trust boundary — tests are gates, not suggestions. Mirrors `Voix/tests/` 84-tests discipline and `Verdandi/ROADMAP.md:Tooling backlog` fuzzing, but for DNS packet soil.

## Levels

### 1. Unit (`cargo test`)

```bash
cargo test
cargo test -- --nocapture
RUST_LOG=debug cargo test core::cache --nocapture
```

- `src/core/dnssec/` — `ring` vs `botan` provider parity (if `--features botan-crypto`): same `RRSIG` verifies both.
- `src/core/cache/` — `proptest` TTL expiry, LRU eviction, `N` stale-serve.
- `src/net/proxy.rs` — `PROXY v1`/`v2` parse, allowlist rejection, `CRLF` strictness.
- `src/api/` — `rbac` `auditor` cannot `POST /api/deleteZone` (`ROADMAP.md:M7` gate mocked).

### 2. Property & fuzz

```bash
cargo fuzz run dns_parse -- -max_total_time=60
cargo test --features botan-crypto -- dnssec_proptest
```

- `libFuzzer` target `fuzz/fuzz_targets/dns_parse.rs` feeds raw `UDP` bytes to `hickory-proto`+Heimdallr glue — no panic on `0..512` crafted inputs.
- `DNSSEC` `NSEC3` SHA-1 truncated inputs (`THREATS.md:Attack surface 1` analogue).
- Planned: `quinn` `ClientHello` tampering corpus.

### 3. Integration (requires ports)

```bash
cargo test --test integration -- --ignored
# spawns heimdallr on 5353/5381 (unpriv), digs it, compares vs Technitium
./scripts/regression.sh
```

`scripts/regression.sh`:

```bash
#!/bin/sh
set -e
HEIMDALLR=target/debug/heimdallr
TECHNIUM_DIG=@127.0.0.1  # existing Technitium at ~/Work/Technitium if free
heimdallr --config config/heimdallr.toml --listen 127.0.0.1:5353 --api-listen 127.0.0.1:5381 &
PID=$!
trap "kill $PID" EXIT
sleep 1
dig @127.0.0.1 -p 5353 example.test A | grep -q "ANSWER: 1"
dig @127.0.0.1 -p 5353 example.test. AAAA | grep -q "NXDOMAIN\|NOERROR"
kdig @127.0.0.1 -p 853 +tls example.test | grep -q "ANSWER"
curl -sk https://127.0.0.1:8443/dns-query?dns=$(echo -n "example.test" | ./scripts/encode-doh) | hexdump -C
```

### 4. Interop

- `ldns-verify-zone` for `M3` signed zones.
- `delv @127.0.0.1 -p 5353` for validation (`valid`/`bogus`/`insecure`).
- `Flamethrower`/`dnsperf` for `ROADMAP.md:M9` bench `>60k qps` cached (vs `Technitium/README.md:37` `100k` on `i7-8700`).

## Quality gates (CI — `CONTRIBUTING.md`)

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo audit
cargo deny check
cargo tree | grep -iE "openssl|bssl|aws-lc" && exit 1 # bans OpenSSL/BoringSSL/aws-lc in default
cargo test && cargo test --features botan-crypto
```

Like `Verdandi/AGENTS.md:96-102` `Verification checklist`, no PR merges if any line fails.

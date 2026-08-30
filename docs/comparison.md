# Comparison — Heimdallr vs Technitium

| Area | Technitium | Heimdallr | Parity plan |
|---|---|---|---|
| Core | C# .NET, custom wire format | Rust hickory-proto+hickory-server (ring) | M1–M3 |
| Runtime | GC + libmsquic for DoQ/H3 | no GC, quinn+rustls ring | no native msquic |
| Crypto | C# crypto provider | ring default, botan opt-in | no OpenSSL/BoringSSL default |
| Cache | serve stale, prefetch, persistent | core/cache/ M1/M6 | hit-for-hit |
| DNSSEC | RSA/ECDSA/EdDSA, NSEC+NSEC3 | same via ring + botan alt | M3 |
| Encrypted | DoT, DoH (H/1.1/2/3), DoQ, PROXY v1/v2 | same (M4) | M4 |
| Records | DANE, SVCB/HTTPS, URI, SSHFP, DNAME, ANAME, APP | same M5 | CLI parity |
| Zones | Primary/Secondary/Stub/CondFwd+catalog, AXFR/IXFR/NOTIFY | same M2/M9 | import zip in M9 |
| Transfers | TSIG, XFR-over-TLS+QUIC | same M9 | interop |
| Filter | AdvancedBlocking, DnsBlockList, BlockPage, DNRP | core/filter M6 | per-client gate |
| Forwarding | Latency concurrency | resolver.concurrency + M9 import | M6/M9 |
| Behaviors | QNAME min, 0x20, CNAME cloaking, ECS, EDE, DNS64 | same M5 | tcpdump visible |
| DHCP | multi-scope | dhcp/ M8 | lease gate |
| Console | Web dashboard + REST API | axum :5380 API M6–M7 | JSON shapes match |
| Auth | RBAC + API tokens + TOTP + OIDC | api/auth argon2id+TOTP+OIDC | M7 |
| Clustering | manage N instances | cluster/ M8 | 2-node gate |
| Observability | Stats + query logs + query log export | query.log JSON + sqlite, Prometheus | M6 |
| Apps | 27 per-app projects | apps/ WASM sandboxed DnsApp trait | apps2.json compat |
| Packaging | Windows + install.sh + systemd + Docker | systemd only (Windows deferred) | docs/operation.md |
| Bench | 100k req/s | >60k qps cached M9 | tokio batched recvmmsg |

## License difference

GPL-3.0 network use is not conveying. OSL-3.0 External Deployment forces any hosted modifier to publish source.

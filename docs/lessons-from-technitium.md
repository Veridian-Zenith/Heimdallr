# Lessons from Technitium

Heimdallr learns from living on Technitium DNS Server.

## What Technitium gets right (keep)

1. **Zero-config that still shows its work.** Stats + Query logs make the network legible. Keep M6 logs+metrics first-class.
2. **Apps as the escape hatch.** AdvancedBlocking per-client regex + AdvancedForwarding + DnsBlockList + SplitHorizon mean power users never fork core. WASM must be equally wide.
3. **Forwarder concurrency over static priority.** Latency-based selection with concurrency is real-world snappy.
4. **Encrypted path parity.** DoT/DoH/DoQ as both self-hosted services and forwarder protocols is not optional for privacy.

## What to design out from day one

| Scar | Technitium shape | Heimdallr encoding |
|---|---|---|
| libmsquic native dep | apt install libmsquic, skip if no QUIC | Pure quinn+rustls ring — zero native QUIC to install |
| GPL-3.0 hides hosted mods | Forks can run unpublished | OSL-3.0 External Deployment — hosted keeps copyleft |
| C# crypto hides agility | Adding GOST/EdDSA is core rebuild | ring default + botan-crypto feature — agility behind a trait |
| Query Logs PostgreSQL split | sqlite/mysql/mssql/pgsql dialect fan-out | sqlite default + single postgres exporter |
| Monolithic WebServiceApi | dashboard+zones+logs+settings+Dhcp in one file | axum routed modules — same API shapes, boundary-clean |
| ANAME/APP proprietary | No import story | M5 ANAME flattening + M9 import of zip zones |

## Tuning defaults

- Caching: serve-stale on, prefetch=2.
- QNAME minimization on by default, 0x20 off (middlebox compat).
- Forwarders: concurrency 2, timeout 2s.
- Observability: query.log json + Prometheus metrics.

# RFC Coverage

Target parity `Technitium/DnsServer/SupportedRFCs.md` + `README.md:29-92`. Table mirrors `Galdr/README.md:2-20` philosophy — one row per capability, with Technitium ref.

## Core wire

| RFC | Title | Status planned |
|---|---|---|
| 1035 + 1034 | DNS base | M1 — `hickory-proto` |
| 6891 | `EDNS(0)` | M1 |
| 7766 | `DNS over TCP` (+ pipelining `§7` out-of-order) | M1 — `net/tcp.rs` |
| 8482 | `ANY` `RCODE` | M1 |

## Encrypted transports

| RFC | Title | Status |
|---|---|---|
| 7858 | `DoT` | M4 — `rustls:ring` |
| 8484 | `DoH` + `HTTP/1.1`/`2` (`axum`) | M4 |
| 9250 | `DoQ` (+ `HTTP/3` later) | M4 — `quinn:ring` no `libmsquic` |
| `PROXY protocol` | `v1`/`v2` for `UDP`+`TCP` (`HAProxy` spec) | M4 — `net/proxy.rs` |

## Resolution behaviors

| RFC | Title | Status |
|---|---|---|
| 9156 | `QNAME minimization` | M5 |
| `draft-vixie-dnsext-dns0x20-00` | `QNAME` case randomization | M5 |
| 7871 | `ECS` (`EDNS Client Subnet`) | M5 (`M1` stub) |
| 8914 | `Extended DNS Errors` | M1 |
| 7314 | `EDNS EXPIRE` | M5 |
| Latency concurrency | Technitium `forwarder concurrency` | M6 |

## Records

| RFC | Title | Status |
|---|---|---|
| 6698 | `DANE TLSA` + auto hash from `PEM` | M5 |
| 9460 | `SVCB`/`HTTPS` | M5 |
| 7553 | `URI` | M5 |
| 4255 | `SSHFP` | M5 |
| 6672 | `DNAME` | M5 |
| `ANAME`/`APP` | Technitium proprietary (`ANAME` flattening, `APP` record dispatch) | M5 |

## DNSSEC

| RFC | Title | Status |
|---|---|---|
| 4033-4035 | `DNSSEC` `RSA`/`ECDSA`/`EdDSA` (`NSEC`/`NSEC3`) | M3 — `ring` (`botan` alt) |
| 5155 | `NSEC3` | M3 |
| 8976 | `ZONEMD` (secondary validation) | M3/M9 |
| 8945 | `TSIG` (zone XFR) | M9 |
| 1995-1996 | `IXFR`/`NOTIFY` | M2/M9 |
| 9103 | `XFR-over-TLS` | M9 |
| 9250 | `XFR-over-QUIC` | M9 |
| 9432 | Catalog zones | M2 |
| 2136 | `Dynamic Updates` | M9 |

## Zones & transfers

| RFC | Title | Status |
|---|---|---|
| `AXFR` | `RFC 5936` | M2 |
| 6147 | `DNS64` (`Dns64App` parity) | M5 |
| 5782 | `DNSBL`/`RBL` hosting | M6 |

## Parity extensions (Technitium `README.md:50-92`)

`SplitHorizonApp` / `Geo*App` via `apps/` + geo `MaxMind` (M7), `FailoverApp` health checks + `WeightedRoundRobin`/`FilterAaaa` (M9), persistent cache save/restore (M6), clustering (M8), DHCP (M8).

## Implementation notes

- `hickory-proto` already covers most of `§Core wire`+`Zones`+`Records`; Heimdallr adds `ANAME` flattening + `APP` dispatch on top.
- No `OpenSSL` — `dnssec-ring` + `rustls:ring` + `quinn:ring` keeps `cargo tree` clean; `Botan` behind `botan-crypto` feature covers `NSEC3` `SHA-1`/`GOST` agility if needed without pulling `aws-lc-rs`/`BoringSSL`.

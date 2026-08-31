# RFC Coverage

Target parity with Technitium DNS Server's supported RFCs.

## Core wire

| RFC | Title | Status |
|---|---|---|
| 1035 + 1034 | DNS base | M1 — `hickory-proto` ✅ |
| 6891 | EDNS(0) | M1 ✅ |
| 7766 | DNS over TCP (+ pipelining §7 out-of-order) | M1 ✅ |
| 8482 | ANY RCODE | M1 ✅ |

## Encrypted transports

| RFC | Title | Status |
|---|---|---|
| 7858 | DoT | M4 — `rustls:ring` |
| 8484 | DoH + HTTP/1.1/2 (`axum`) | M4 |
| 9250 | DoQ | M4 — `quinn:ring` |
| PROXY protocol | v1/v2 for UDP+TCP | M4 |

## Resolution behaviors

| RFC | Title | Status |
|---|---|---|
| 9156 | QNAME minimization | M5 |
| 7871 | ECS (EDNS Client Subnet) | M5 (M1 stub) |
| 8914 | Extended DNS Errors | M1 ✅ |
| 7314 | EDNS EXPIRE | M5 |

## Records

| RFC | Title | Status |
|---|---|---|
| 6698 | DANE TLSA | M5 |
| 9460 | SVCB/HTTPS | M5 |
| 7553 | URI | M5 |
| 4255 | SSHFP | M5 |
| 6672 | DNAME | M5 |
| ANAME/APP | Proprietary (ANAME flattening, APP dispatch) | M5 |

## DNSSEC

| RFC | Title | Status |
|---|---|---|
| 4033-4035 | DNSSEC RSA/ECDSA/EdDSA (NSEC/NSEC3) | M3 — `ring` |
| 5155 | NSEC3 | M3 |
| 8976 | ZONEMD | M3/M9 |
| 8945 | TSIG | M9 |
| 1995-1996 | IXFR/NOTIFY | M2 ✅ (NOTIFY) / M9 (IXFR) |
| 9103 | XFR-over-TLS | M9 |
| 9250 | XFR-over-QUIC | M9 |
| 9432 | Catalog zones | M2 ✅ |
| 2136 | Dynamic Updates | M9 |

## Zones & transfers

| RFC | Title | Status |
|---|---|---|
| AXFR | RFC 5936 | M2 ✅ |
| 6147 | DNS64 | M5 |
| 5782 | DNSBL/RBL hosting | M6 |

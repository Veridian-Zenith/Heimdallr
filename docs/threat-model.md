# Threat Model

Heimdallr is a DNS server — every UDP packet is untrusted, every TCP/TLS/QUIC handshake is attacker-controlled before authentication.

## Trusted Computing Base

| Metric | Heimdallr (Rust) |
|---|---|
| LoC | ~8k Rust + hickory/quinn/rustls/ring — minimal native |
| External C deps | 0 default (ring asm only); optional libbotan-2 |
| OpenSSL | 0 (`cargo tree | grep openssl` empty) |
| Config | TOML + typed serde (fails closed) |

## Threat actor

**Unauthenticated network attacker** sending crafted UDP/TCP/TLS/QUIC/HTTPS packets to :53/:853/:443; secondarily **authenticated API user** (:5380) attempting privilege escalation.

## Attack surface

### 1. Packet parsing (`src/net/`, `hickory-proto`)
- **Risk:** Parser CVEs, label compression pointer loops, RDLENGTH OOM, poisoned cache.
- **Mitigations:** Rust `forbid(unsafe_code)`, `hickory-proto` fuzzed upstream, EDNS(0) bufsize caps, panic=abort.

### 2. Cache poisoning (off-path + on-path)
- **Risks:** TXID/port brute force, Kaminsky, NS glue hijack, CNAME cloaking bypass.
- **Mitigations:** Randomized TXID+source port, QNAME minimization RFC 9156, DNSSEC validation (M3), CNAME cloaking block.

### 3. Encrypted transports (M4)
- **Risks:** rustls/quinn handshake DoS, SNI leak, downgrade to cleartext forwarder.
- **Mitigations:** rustls:ring, quinn:ring, forward_protocol pinned, PROXY protocol allowlist.

### 4. Zone transfers
- **Risks:** Unauthorized AXFR dump, IXFR replay.
- **Mitigations:** allow-transfer ACL, ZONEMD verification (M9), NOTIFY ACL.

### 5. Web API :5380 (M7)
- **Risks:** Auth bypass, token theft, RBAC bypass, XSS, CSRF.
- **Mitigations:** argon2id, HMAC-scoped API tokens, RBAC, TOTP/OIDC, CORS deny-by-default, CSP, rate limiting.

### 6. Configuration tampering
- **Mitigations:** Owner root:heimdallr 0640, path traversal rejection, --check-config fails closed.

### 7. Persistence
- **Mitigations:** cache.bin 0600, validated header, query.log rotation, symlink-resistant open.

### 8. Supply chain
- **Mitigations:** Cargo.lock committed, cargo audit/deny in CI, cargo tree openssl ban.

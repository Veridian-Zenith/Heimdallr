# Configuration

`heimdallr` reads `TOML` (like `Galdr/config/galdr.toml`) at `/etc/heimdallr/heimdallr.toml` by default. CLI `--config` overrides. Mirrors `Technitium DnsServer/DnsServerCore` settings (`WebServiceSettingsApi`) but flat `TOML`, not JSON API storage.

## Quick start

```bash
sudo install -Dm644 config/heimdallr.toml /etc/heimdallr/heimdallr.toml
heimdallr --config /etc/heimdallr/heimdallr.toml --listen 0.0.0.0:53 --api-listen 0.0.0.0:5380
RUST_LOG=debug heimdallr  # tracing env-filter
```

## Reference (`config/heimdallr.toml`)

```toml
# Network (Technitium parity: listeners)
listen = ["0.0.0.0:53", "[::]:53"]          # UDP+TCP together
listen_tls = ["0.0.0.0:853"]               # DoT (rustls:ring) - ROADMAP.md:M4
listen_quic = ["0.0.0.0:853"]              # DoQ (quinn:ring)
listen_https = ["0.0.0.0:443"]             # DoH (axum+h2, /dns-query)

# Recursive resolver (hickory-resolver)
[resolver]
forwarders = ["1.1.1.1:53", "8.8.8.8:53"]   # empty => pure recursion from root (named.root analogue)
forward_protocol = "udp"                   # udp | tcp | dot | doh | doq
qname_minimization = true                  # RFC 9156
qname_randomization = false                # draft-vixie 0x20
ecs = false                                # RFC 7871, forwarder only
concurrency = 2                            # Technitium forwarder concurrency
timeout_ms = 2000

# Cache
[cache]
size = 50000
serve_stale = true                         # stale-while-expire
prefetch = 2                               # prefetch when TTL < N * query count
persistent = "/var/lib/heimdallr/cache.bin"

# Authoritative zones (repeatable)
[[zones]]
name = "example.test."
kind = "primary"                           # primary | secondary | stub | conditional | forwarder
file = "/var/lib/heimdallr/zones/example.test.zone"
# secondary-specific:
# primaries = ["10.0.0.1:53"]
# transfer = "axfr"                        # axfr | ixfr
# notify_retry = "5s"

# DNSSEC
[dnssec]
validation = true                          # recursive/forwarder
anchors = "/var/lib/heimdallr/root-anchors.xml" # like DnsServerCore/root-anchors.xml
signing = false                            # hosted zones
provider = "ring"                          # ring | botan  (botan needs --features botan-crypto)

# Filtering (AdvancedBlockingApp + DnsBlockListApp parity)
[filter]
blocklists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
]
allowlists = []
regex_blocklist = ["^.*\\.ads\\..*$"]
per_client = { "10.0.0.5/32" = { block = false } }
cname_cloaking = true
rebinding = true                           # DnsRebindingProtectionApp

# Proxy (PROXY protocol v1/v2)
[proxy]
enable = false
allow = ["10.0.0.0/24"]
protocol = "v2"                            # v1 | v2

# API + Web console
[api]
listen = "0.0.0.0:5380"
tls_cert = "/etc/heimdallr/cert.pem"       # optional, rustls:ring
tls_key = "/etc/heimdallr/key.pem"

[auth]
# RBAC + tokens (Technitium WebServiceAuthApi parity)
users = [{ name = "admin", password_hash = "$argon2id$..." }]
tokens = [{ name = "automation", value = "hmac-..." }]
totp = true
oidc = false

[log]
level = "info"                             # trace|debug|info|warn
query_log = "/var/log/heimdallr/query.log"
format = "json"                            # json | text

[dhcp]
enable = false
ranges = [{ subnet = "10.0.0.0/24", start = "10.0.0.100", end = "10.0.0.200", router = "10.0.0.1" }]

[cluster]
enable = false
peers = []                                 # ["10.0.0.2:5380"]
```

## File semantics

- Missing keys use defaults from `src/core/config.rs`; `heimdallr --check-config` validates without binding ports.
- Paths are created with `0700`/`0600` (like `Voix/FileUtils` `O_NOFOLLOW` lineage).
- Zone files are standard `RFC 1035` with `$TTL`, `$ORIGIN`, includes.

## API parity

`docs/operation.md:API` maps this `TOML` to `Technitium/DnsServer/APIDOCS.md` `WebServiceJson` endpoints (`/api/settings/get`, `/api/zones/create`, etc.) for migration tooling.

# Configuration

Heimdallr reads TOML at `/etc/heimdallr/config.toml` by default. CLI `--config` overrides.

## Quick start

```bash
sudo install -Dm644 config/config.toml /etc/heimdallr/config.toml
heimdallr --config /etc/heimdallr/config.toml
RUST_LOG=debug heimdallr
```

> [!NOTE]
> Missing keys use defaults. Run `heimdallr --check-config` to validate without binding ports.

## Reference (`config/config.toml`)

<details>
<summary>Full reference (config/config.toml)</summary>

```toml
# Network
listen = ["0.0.0.0:53", "[::]:53"]
listen_tls = ["0.0.0.0:853"]
listen_quic = ["0.0.0.0:853"]
listen_https = ["0.0.0.0:443"]

# Recursive resolver
[resolver]
forwarders = ["1.1.1.1:53", "8.8.8.8:53"]
forward_protocol = "udp"
qname_minimization = true
qname_randomization = false
ecs = false
concurrency = 2
timeout_ms = 2000

# Cache
[cache]
size = 50000
serve_stale = true
prefetch = 2
persistent = "/var/lib/heimdallr/cache.bin"

# Zones
[[zones]]
name = "example.test."
kind = "primary"
file = "config/zones/live/example.test.zone"

# DNSSEC
[dnssec]
validation = true
anchors = "/var/lib/heimdallr/root-anchors.xml"
signing = false
provider = "ring"

# Filtering
[filter]
blocklists = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
allowlists = []
regex_blocklist = ["^.*\\.ads\\..*$"]
per_client = { "10.0.0.5/32" = { block = false } }
cname_cloaking = true
rebinding = true

# Proxy
[proxy]
enable = false
allow = ["10.0.0.0/24"]
protocol = "v2"

# API
[api]
listen = "0.0.0.0:5380"
tls_cert = ""
tls_key = ""

[auth]
users = [{ name = "admin", password_hash = "$argon2id$..." }]
tokens = []
totp = false
oidc = false

[log]
level = "info"
query_log = ""
format = "json"

[dhcp]
enable = false
ranges = []

[cluster]
enable = false
peers = []
```

</details>

## File semantics

- Missing keys use defaults; `heimdallr --check-config` validates without binding ports.
- Zone files are standard RFC 1035 with `$TTL`, `$ORIGIN`, includes.
- SOA RNAME is auto-injected from `hostadmin` config field.

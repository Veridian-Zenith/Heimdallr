# Configuration

Heimdallr reads TOML at `/etc/heimdallr/config.toml` by default. CLI `--config` overrides.

## Quick start

```bash
sudo ./scripts/install.sh
heimdallr --check-config
RUST_LOG=debug heimdallr
```

> [!NOTE]
> Missing keys use defaults. Run `heimdallr --check-config` to validate without binding ports.

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/health` | Health check (`{"status":"ok","version":"..."}`) |
| `GET /api/info` | Server info (hostname, listen addrs, zones count, DNSSEC, cache, log level) |
| `GET /api/zones` | List all configured zones (name, kind, file, primaries) |
| `GET /api/zones/{name}` | Detail for a single zone |

> [!NOTE]
> API TLS support (`api.tls_cert`/`api.tls_key`) is planned for M4. Currently serves plain HTTP.

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

# Operation

Heimdallr runs as a single static binary. Linux-only; systemd is first-class.

## Prerequisites

- Rust 2024 edition, no OpenSSL (pure ring).
- Optional: libbotan-2 for `--features botan-crypto`.

## Build

```bash
cargo build --release
cargo tree | grep -iE "openssl|bssl|aws-lc"  # must be empty
cargo audit
```

## Install (recommended)

```bash
sudo ./scripts/install.sh
```

The install script builds the release binary, creates the `heimdallr` user/group, and installs all files. It detects existing config/zone/systemd files and prompts before overwriting — declined files are placed in `/opt/heimdallr/zones/templates/` as reference templates.

## systemd

> [!IMPORTANT]
> These commands disable `systemd-resolved`. Make sure no other service depends on it before proceeding.

```bash
sudo systemctl disable --now systemd-resolved
sudo systemctl enable --now heimdallr
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
journalctl -u heimdallr -f
```

## CLI

```bash
heimdallr --help
heimdallr --check-config
heimdallr --config /etc/heimdallr/config.toml --listen 127.0.0.1:5353
RUST_LOG=heimdallr=debug,quinn=info heimdallr
```

## API

```bash
curl http://127.0.0.1:5380/api/health   # {"status":"ok","version":"0.3.0-alpha"}
curl http://127.0.0.1:5380/api/info      # server info (listen, zones, cache, DNSSEC)
curl http://127.0.0.1:5380/api/zones     # list all configured zones
curl http://127.0.0.1:5380/api/zones/example.test.  # zone detail
```

## Observability

- Tracing: `RUST_LOG` env-filter, `query.log` JSON lines.
- Metrics: cache hit ratio, DNSSEC validation outcome (M6 Prometheus).

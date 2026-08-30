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

## systemd

```bash
sudo install -Dm755 target/release/heimdallr /usr/local/bin/heimdallr
sudo install -Dm644 config/config.toml /etc/heimdallr/config.toml
sudo install -Dm644 packaging/systemd/heimdallr.service /etc/systemd/system/heimdallr.service
sudo systemctl daemon-reload
sudo systemctl disable --now systemd-resolved
sudo systemctl enable --now heimdallr
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
journalctl -u heimdallr -f
```

Service file (`packaging/systemd/heimdallr.service`):

```ini
[Unit]
Description=Heimdallr DNS (from-zero, OSL-3.0)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=heimdallr
Group=heimdallr
ExecStart=/usr/local/bin/heimdallr --config /etc/heimdallr/config.toml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

## CLI

```bash
heimdallr --help
heimdallr --check-config
heimdallr --config /etc/heimdallr/config.toml --listen 127.0.0.1:5353
RUST_LOG=heimdallr=debug,quinn=info heimdallr
```

## Observability

- Tracing: `RUST_LOG` env-filter, `query.log` JSON lines.
- Metrics: cache hit ratio, DNSSEC validation outcome (M6 Prometheus).

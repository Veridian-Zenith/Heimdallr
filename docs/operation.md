# Operation

Heimdallr runs as a single static binary — `cargo build --release` → `target/release/heimdallr` — unlike `Technitium/DnsServer/build.md:4-11` Windows setup. Linux-only; `systemd`+`Docker` are first-class (same as `DnsServer/build.md:63-98` but `heimdallr`).

## Prerequisites

- `Rust 2024` edition (`Galdr/README.md:192` same), no `libmsquic`, no `OpenSSL` (pure `ring`).
- Optional for `Botan` feature: `libbotan-2` (`extra/botan`) — `cargo build --features botan-crypto`.
- `systemd` or `Docker`.

## Build

```bash
# Default (pure ring, no BoringSSL/aws-lc)
cargo build --release  # profile.release: opt-level = "z", lto, strip (Cargo.toml)

# With Botan HSM option
cargo build --release --features botan-crypto

# Verify crypto provenance
cargo tree | grep -ivE "ring|quinn|rustls" | grep -iE "openssl|bssl|aws-lc" # must be empty
cargo audit
```

## systemd (parity `build.md:70-76`)

```bash
sudo install -Dm755 target/release/heimdallr /usr/local/bin/heimdallr
sudo install -Dm644 config/heimdallr.toml /etc/heimdallr/heimdallr.toml
sudo install -Dm644 packaging/systemd/heimdallr.service /etc/systemd/system/heimdallr.service
sudo systemctl daemon-reload
sudo systemctl disable --now systemd-resolved  # free :53 like build.md:71-72
sudo systemctl enable --now heimdallr
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
journalctl -u heimdallr -f
# curl http://127.0.0.1:5380/ -> console
```

`packaging/systemd/heimdallr.service` template:

```ini
[Unit]
Description=Heimdallr DNS (from-zero, OSL-3.0)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=heimdallr
Group=heimdallr
ExecStart=/usr/local/bin/heimdallr --config /etc/heimdallr/heimdallr.toml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

## Docker (parity `build.md:88-98` + `docker-compose.yml`)

```bash
docker build -t heimdallr:latest .
docker compose up -d   # see docker-compose.yml
# compose maps 53/53+53/tcp+853/tcp+853/udp+5380, volumes /var/lib/heimdallr
```

No `libmsquic` layer — image is ` scratch`/`distroless` + binary only (`Galdr` `profile.release:strip` style).

## CLI

```bash
heimdallr --help
heimdallr --check-config                # validate TOML without binding
heimdallr --config /etc/heimdallr/heimdallr.toml --listen 0.0.0.0:5353  # non-priv test
RUST_LOG=heimdallr=debug,quinn=info heimdallr
```

## API :5380 (Technitium `APIDOCS.md` parity)

- `POST /api/login` (`user`/`pass`/`token` → `jwt`)
- `GET/POST /api/zones/*`, `/api/records/*`, `/api/settings/*`, `/api/dhcp/*`, `/api/logs/*` — `JSON` shapes match `DnsServerCore/WebService*.cs` for migration.
- `GET /api/metrics` → `Prometheus` (unlike Technitium stats page only).

Console is `Axum` static files at `/` with dark mode (Technitium `DnsServerCore/www` analogue).

## Observability

- Tracing: `RUST_LOG` env-filter (`tracing-subscriber`), `query.log` `JSON` lines with `client_ip`, `qname`, `qtype`, `rcode`, `latency_ms`.
- Metrics: cache hit ratio, `DNSSEC` validation outcome, `DoT`/`DoH`/`DoQ` handshakes.
- Backup: `tar -C /var/lib/heimdallr zones/ cache.bin heindallr.toml` — unlike `Query Logs (PostgreSQL).zip` legacy, export is `sqlite`/`json`.

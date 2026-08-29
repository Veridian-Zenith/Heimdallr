#!/bin/sh
set -e
cargo build --release
sudo install -Dm755 target/release/heimdallr /usr/local/bin/heimdallr
sudo install -Dm644 config/heimdallr.toml /etc/heimdallr/heimdallr.toml
sudo install -Dm644 packaging/systemd/heimdallr.service /etc/systemd/system/heimdallr.service
sudo systemctl daemon-reload
echo "installed: /usr/local/bin/heimdallr + /etc/heimdallr/heimdallr.toml + heimdallr.service"

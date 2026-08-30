#!/bin/sh
set -e

BIN_SRC="target/release/heimdallr"
BIN_DST="/opt/heimdallr/heimdallr"
TEMPLATES_SRC="config/zones/templates"
TEMPLATES_DST="/opt/heimdallr/zones/templates"
LIVE_SRC="config/zones/live"
LIVE_DST="/etc/heimdallr/zones"
CFG_SRC="config/config.toml"
CFG_DST="/etc/heimdallr/config.toml"

echo "==> building release..."
cargo build --release

echo "==> installing binary..."
sudo install -Dm755 "$BIN_SRC" "$BIN_DST"

echo "==> installing zone templates..."
sudo mkdir -p "$TEMPLATES_DST"
sudo cp -r "$TEMPLATES_SRC"/. "$TEMPLATES_DST/"

echo "==> installing default zone files..."
sudo mkdir -p "$LIVE_DST"
sudo cp -rn "$LIVE_SRC"/. "$LIVE_DST/" 2>/dev/null || true  # don't overwrite existing

echo "==> installing config..."
sudo install -Dm644 "$CFG_SRC" "$CFG_DST"

echo "==> installing systemd unit..."
sudo install -Dm644 packaging/systemd/heimdallr.service /etc/systemd/system/heimdallr.service
sudo systemctl daemon-reload

echo "installed:"
echo "  $BIN_DST"
echo "  $TEMPLATES_DST/  (templates)"
echo "  $LIVE_DST/       (live zone files)"
echo "  $CFG_DST"
echo "  heimdallr.service"

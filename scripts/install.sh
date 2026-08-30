#!/bin/sh
set -e

# --- paths ---
BIN_SRC="target/release/heimdallr"
BIN_DST="/opt/heimdallr/heimdallr"
TEMPLATES_SRC="config/zones/templates"
TEMPLATES_DST="/opt/heimdallr/zones/templates"
LIVE_SRC="config/zones/live"
LIVE_DST="/etc/heimdallr/zones"
CFG_SRC="config/config.toml"
CFG_DST="/etc/heimdallr/config.toml"
SYSUSER_SRC="packaging/sysusers/heimdallr.conf"
SYSUSER_DST="/etc/sysusers.d/heimdallr.conf"
SYSTEMD_SRC="packaging/systemd/heimdallr.service"
SYSTEMD_DST="/etc/systemd/system/heimdallr.service"

# --- build ---
echo "==> building release..."
cargo build --release

# --- user/group ---
echo "==> ensuring heimdallr user/group..."
if ! getent group heimdallr >/dev/null 2>&1; then
    sudo groupadd --system heimdallr
fi
if ! getent passwd heimdallr >/dev/null 2>&1; then
    sudo useradd --system --gid heimdallr --home-dir /var/lib/heimdallr \
        --shell /usr/sbin/nologin --no-create-home heimdallr
fi

# --- directories ---
echo "==> creating directories..."
sudo mkdir -p /opt/heimdallr /opt/heimdallr/zones/templates
sudo mkdir -p /etc/heimdallr/zones
sudo mkdir -p /var/lib/heimdallr
sudo mkdir -p /var/log/heimdallr

# --- install binary ---
echo "==> installing binary..."
sudo install -Dm755 "$BIN_SRC" "$BIN_DST"
sudo chown heimdallr:heimdallr "$BIN_DST"

# --- install zone templates ---
echo "==> installing zone templates..."
sudo cp -r "$TEMPLATES_SRC"/. "$TEMPLATES_DST/"

# --- install default zone files (don't overwrite existing) ---
echo "==> installing default zone files..."
sudo cp -rn "$LIVE_SRC"/. "$LIVE_DST/" 2>/dev/null || true

# --- install config (don't overwrite existing) ---
echo "==> installing config..."
if [ ! -f "$CFG_DST" ]; then
    sudo install -Dm644 "$CFG_SRC" "$CFG_DST"
else
    echo "    $CFG_DST already exists, skipping (edit manually if needed)"
fi

# --- install sysusers ---
echo "==> installing sysusers config..."
sudo install -Dm644 "$SYSUSER_SRC" "$SYSUSER_DST"

# --- install systemd unit ---
echo "==> installing systemd unit..."
sudo install -Dm644 "$SYSTEMD_SRC" "$SYSTEMD_DST"

# --- ownership ---
echo "==> setting ownership..."
sudo chown -R heimdallr:heimdallr /opt/heimdallr
sudo chown -R heimdallr:heimdallr /etc/heimdallr
sudo chown -R heimdallr:heimdallr /var/lib/heimdallr
sudo chown -R heimdallr:heimdallr /var/log/heimdallr

# Let's Encrypt certs are root:root 644 — heimdallr user needs read access
# Add heimdallr to the ssl-cert group if it exists (Debian/Ubuntu),
# otherwise setfacl for read access
if getent group ssl-cert >/dev/null 2>&1; then
    echo "==> adding heimdallr to ssl-cert group..."
    sudo usermod -aG ssl-cert heimdallr
elif command -v setfacl >/dev/null 2>&1; then
    echo "==> granting cert read access via ACL..."
    sudo setfacl -R -m u:heimdallr:rX /etc/letsencrypt/live /etc/letsencrypt/archive
fi

# --- reload and enable ---
echo "==> reloading systemd..."
sudo systemctl daemon-reload
sudo systemctl enable heimdallr.service

echo ""
echo "installed:"
echo "  $BIN_DST"
echo "  $TEMPLATES_DST/  (templates)"
echo "  $LIVE_DST/       (live zone files)"
echo "  $CFG_DST"
echo "  $SYSUSER_DST"
echo "  $SYSTEMD_DST"
echo ""
echo "user: heimdallr:heimdallr"
echo ""
echo "to start: sudo systemctl start heimdallr"
echo "to view:  sudo journalctl -u heimdallr -f"

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

# --- helper: prompt y/n, return 0 for yes, 1 for no ---
prompt_overwrite() {
    _path="$1"
    _default="${2:-n}"
    if [ "$_default" = "y" ]; then
        _hint="Y/n"
    else
        _hint="y/N"
    fi
    printf "  Overwrite %s? [%s] " "$_path" "$_hint"
    read -r _answer </dev/tty
    _answer="${_answer:-$_default}"
    case "$_answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

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

# --- install zone templates (always update — these are reference material) ---
echo "==> installing zone templates..."
sudo cp -r "$TEMPLATES_SRC"/. "$TEMPLATES_DST/"

# --- install config ---
echo "==> installing config..."
if [ -f "$CFG_DST" ]; then
    if prompt_overwrite "$CFG_DST" "n"; then
        sudo install -Dm644 "$CFG_SRC" "$CFG_DST"
    else
        echo "    keeping existing $CFG_DST"
        echo "    new config template placed in $TEMPLATES_DST/config.toml"
        sudo cp -f "$CFG_SRC" "$TEMPLATES_DST/config.toml"
    fi
else
    sudo install -Dm644 "$CFG_SRC" "$CFG_DST"
fi

# --- install zone files ---
echo "==> installing zone files..."
_existing_zones=""
for _zone_file in "$LIVE_SRC"/*.zone; do
    [ -f "$_zone_file" ] || continue
    _zone_name="$(basename "$_zone_file")"
    if [ -f "$LIVE_DST/$_zone_name" ]; then
        _existing_zones="$_existing_zones $_zone_name"
    fi
done

if [ -n "$_existing_zones" ]; then
    echo "  existing zone files found:$_existing_zones"
    if prompt_overwrite "zone files in $LIVE_DST" "n"; then
        sudo cp -f "$LIVE_SRC"/*.zone "$LIVE_DST/" 2>/dev/null || true
    else
        echo "    keeping existing zone files"
        echo "    new zone templates in $TEMPLATES_DST/"
        for _zone_file in "$LIVE_SRC"/*.zone; do
            [ -f "$_zone_file" ] || continue
            sudo install -Dm644 "$_zone_file" "$TEMPLATES_DST/$(basename "$_zone_file")"
        done
    fi
else
    sudo cp -f "$LIVE_SRC"/*.zone "$LIVE_DST/" 2>/dev/null || true
fi

# --- install sysusers ---
echo "==> installing sysusers config..."
if [ -f "$SYSUSER_DST" ]; then
    if prompt_overwrite "$SYSUSER_DST" "n"; then
        sudo install -Dm644 "$SYSUSER_SRC" "$SYSUSER_DST"
    else
        echo "    keeping existing $SYSUSER_DST"
    fi
else
    sudo install -Dm644 "$SYSUSER_SRC" "$SYSUSER_DST"
fi

# --- install systemd unit ---
echo "==> installing systemd unit..."
if [ -f "$SYSTEMD_DST" ]; then
    if prompt_overwrite "$SYSTEMD_DST" "n"; then
        sudo install -Dm644 "$SYSTEMD_SRC" "$SYSTEMD_DST"
    else
        echo "    keeping existing $SYSTEMD_DST"
        echo "    new service file placed in $TEMPLATES_DST/heimdallr.service"
        sudo cp -f "$SYSTEMD_SRC" "$TEMPLATES_DST/heimdallr.service"
    fi
else
    sudo install -Dm644 "$SYSTEMD_SRC" "$SYSTEMD_DST"
fi

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
echo "  $TEMPLATES_DST/  (templates — always updated)"
echo "  $LIVE_DST/       (live zone files)"
echo "  $CFG_DST"
echo "  $SYSUSER_DST"
echo "  $SYSTEMD_DST"
echo ""
echo "user: heimdallr:heimdallr"
echo ""
echo "to start: sudo systemctl start heimdallr"
echo "to view:  sudo journalctl -u heimdallr -f"

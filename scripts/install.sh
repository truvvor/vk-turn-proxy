#!/bin/bash
# One-time bootstrap on the deployment server.
# Creates required directories, installs the systemd template unit, and
# seeds example env files. Idempotent: existing env files are left alone.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root (try: sudo $0)" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="/opt/vk-turn-proxy"
CONFIG_DIR="/etc/vk-turn-proxy"
UNIT_PATH="/etc/systemd/system/vk-turn-proxy@.service"

install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 "$CONFIG_DIR"

install -m 0644 "$REPO_DIR/deploy/vk-turn-proxy@.service" "$UNIT_PATH"

# Refuse to seed an env file whose default LISTEN port is already taken by
# something else on this host (xray, wireguard, etc.). This protects the
# operator from clobbering an unrelated service on first install.
port_owner() {
    local port="$1"
    ss -ulnH "sport = :$port" 2>/dev/null | awk 'NR==1{print $0}'
}

for instance in udp vless; do
    target="$CONFIG_DIR/$instance.env"
    if [ ! -e "$target" ]; then
        example="$REPO_DIR/deploy/$instance.env.example"
        listen=$(awk -F= '/^LISTEN=/{print $2; exit}' "$example")
        port="${listen##*:}"
        if owner=$(port_owner "$port") && [ -n "$owner" ]; then
            echo "Skipping $target: UDP port $port already in use:" >&2
            echo "    $owner" >&2
            echo "    Edit $example or set a different LISTEN port before re-running." >&2
            continue
        fi
        install -m 0640 "$example" "$target"
        echo "Created $target — edit CONNECT before enabling the instance."
    else
        echo "$target already exists, leaving as-is."
    fi
done

systemctl daemon-reload

cat <<'MSG'

Bootstrap complete. Next steps:
  1. Edit /etc/vk-turn-proxy/udp.env (and/or vless.env) and set CONNECT=...
  2. Place the server binary at /opt/vk-turn-proxy/server.
     (The CI deploy workflow does this automatically; for manual install:
        sudo install -m 0755 ./dist/server /opt/vk-turn-proxy/server)
  3. Enable + start the desired instance(s):
        sudo systemctl enable --now vk-turn-proxy@udp.service
        sudo systemctl enable --now vk-turn-proxy@vless.service
  4. Watch it run:
        systemctl status 'vk-turn-proxy@*'
        journalctl -u 'vk-turn-proxy@udp' -f
MSG

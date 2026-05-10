#!/bin/bash
# One-time bootstrap on the deployment server.
# Creates required directories, installs the systemd template unit, and
# seeds env files. Idempotent: existing env files are left alone.
#
# Optional env vars:
#   UDP_CONNECT    backend addr for the udp instance, e.g. 127.0.0.1:51820
#   UDP_LISTEN     LISTEN value for udp (default 0.0.0.0:56000)
#   VLESS_CONNECT  backend addr for the vless instance, e.g. 127.0.0.1:8443
#   VLESS_LISTEN   LISTEN value for vless (default 0.0.0.0:56001)
#
# When *_CONNECT is provided, install.sh writes the env file and enables
# the corresponding systemd unit so the very first deploy can bring it up
# without further manual steps.
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

port_owner() {
    local port="$1"
    ss -ulnH "sport = :$port" 2>/dev/null | awk 'NR==1{print $0}'
}

# Default LISTEN values; respect overrides from env.
UDP_LISTEN_DEFAULT="0.0.0.0:56000"
VLESS_LISTEN_DEFAULT="0.0.0.0:56001"

write_env() {
    local instance="$1" listen="$2" connect="$3" extra="$4"
    local target="$CONFIG_DIR/$instance.env"
    local port="${listen##*:}"

    if [ -e "$target" ]; then
        echo "$target already exists, leaving as-is."
        return 0
    fi
    if owner=$(port_owner "$port") && [ -n "$owner" ]; then
        echo "Refusing to write $target: UDP port $port is already in use:" >&2
        echo "    $owner" >&2
        echo "    Pick a different LISTEN port (set ${instance^^}_LISTEN) and re-run." >&2
        return 1
    fi
    umask 027
    cat > "$target" <<EOF
LISTEN=${listen}
CONNECT=${connect}
EXTRA_ARGS=${extra}
EOF
    chmod 0640 "$target"
    echo "Wrote $target (LISTEN=${listen} CONNECT=${connect})."
}

seed_example() {
    local instance="$1"
    local target="$CONFIG_DIR/$instance.env"
    local example="$REPO_DIR/deploy/$instance.env.example"
    if [ -e "$target" ]; then
        echo "$target already exists, leaving as-is."
        return 0
    fi
    local listen
    listen=$(awk -F= '/^LISTEN=/{print $2; exit}' "$example")
    local port="${listen##*:}"
    if owner=$(port_owner "$port") && [ -n "$owner" ]; then
        echo "Skipping $target: UDP port $port already in use:" >&2
        echo "    $owner" >&2
        return 0
    fi
    install -m 0640 "$example" "$target"
    echo "Created $target — edit CONNECT before enabling the instance."
}

if [ -n "${UDP_CONNECT:-}" ]; then
    write_env udp "${UDP_LISTEN:-$UDP_LISTEN_DEFAULT}" "$UDP_CONNECT" ""
else
    seed_example udp
fi

if [ -n "${VLESS_CONNECT:-}" ]; then
    write_env vless "${VLESS_LISTEN:-$VLESS_LISTEN_DEFAULT}" "$VLESS_CONNECT" "-vless"
else
    seed_example vless
fi

systemctl daemon-reload

if [ -n "${UDP_CONNECT:-}" ]; then
    systemctl enable vk-turn-proxy@udp.service
    echo "Enabled vk-turn-proxy@udp.service (will start on next deploy)."
fi
if [ -n "${VLESS_CONNECT:-}" ]; then
    systemctl enable vk-turn-proxy@vless.service
    echo "Enabled vk-turn-proxy@vless.service (will start on next deploy)."
fi

cat <<'MSG'

Bootstrap complete. Next:
  - If you didn't pass UDP_CONNECT / VLESS_CONNECT above, edit
    /etc/vk-turn-proxy/{udp,vless}.env and `systemctl enable` the unit.
  - Then trigger the GitHub Actions "Deploy" workflow (or push to main).
    The workflow places the binary and (re)starts enabled instances.
  - Watch:  journalctl -u 'vk-turn-proxy@udp' -f
MSG

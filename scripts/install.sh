#!/bin/bash
# One-time bootstrap on the deployment server.
# Creates required directories, installs the systemd template unit, and
# writes env files based on UDP_CONNECT / VLESS_CONNECT env vars.
#
# Required env vars (at least one):
#   UDP_CONNECT    backend addr for the udp instance, e.g. 127.0.0.1:51820
#   VLESS_CONNECT  backend addr for the vless instance, e.g. 127.0.0.1:443
#
# Optional env vars:
#   UDP_LISTEN     LISTEN value for udp (default 0.0.0.0:56000)
#   VLESS_LISTEN   LISTEN value for vless (default 0.0.0.0:56001)
#   FORCE_REWRITE  when "1", overwrite env files even for currently-active
#                  instances (otherwise active instances are preserved)
#
# When *_CONNECT is provided, the env file is created and the systemd unit
# is enabled. If the env file already exists:
#   - the instance is currently active  -> file is preserved (don't disrupt
#     a running daemon); set FORCE_REWRITE=1 to override
#   - the instance is NOT active        -> file is overwritten (recover
#     from a stale env left over from an earlier failed config)

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

UDP_LISTEN_DEFAULT="0.0.0.0:56000"
VLESS_LISTEN_DEFAULT="0.0.0.0:56001"

instance_active() {
    systemctl is-active --quiet "vk-turn-proxy@${1}.service"
}

write_env() {
    local instance="$1" listen="$2" connect="$3" extra="$4"
    local target="$CONFIG_DIR/$instance.env"
    local port="${listen##*:}"

    if [ -e "$target" ]; then
        if instance_active "$instance" && [ "${FORCE_REWRITE:-0}" != "1" ]; then
            echo "$target preserved (vk-turn-proxy@${instance} is active; set FORCE_REWRITE=1 to overwrite)."
            return 0
        fi
        echo "Overwriting $target (instance not active or FORCE_REWRITE=1)."
    fi

    # When the chosen LISTEN port is held by something OTHER than this
    # instance, refuse — picking a different port is the user's call.
    if owner=$(port_owner "$port") && [ -n "$owner" ]; then
        if ! instance_active "$instance"; then
            echo "Refusing to write $target: UDP port $port is held by another process:" >&2
            echo "    $owner" >&2
            echo "    Set ${instance^^}_LISTEN=0.0.0.0:<other-port> and re-run." >&2
            return 1
        fi
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

if [ -n "${UDP_CONNECT:-}" ]; then
    write_env udp "${UDP_LISTEN:-$UDP_LISTEN_DEFAULT}" "$UDP_CONNECT" ""
fi

if [ -n "${VLESS_CONNECT:-}" ]; then
    write_env vless "${VLESS_LISTEN:-$VLESS_LISTEN_DEFAULT}" "$VLESS_CONNECT" "-vless"
fi

systemctl daemon-reload

if [ -n "${UDP_CONNECT:-}" ] && [ -e "$CONFIG_DIR/udp.env" ]; then
    systemctl enable vk-turn-proxy@udp.service
    echo "Enabled vk-turn-proxy@udp.service."
fi
if [ -n "${VLESS_CONNECT:-}" ] && [ -e "$CONFIG_DIR/vless.env" ]; then
    systemctl enable vk-turn-proxy@vless.service
    echo "Enabled vk-turn-proxy@vless.service."
fi

cat <<'MSG'

install.sh complete. Trigger the GitHub Actions "Deploy" workflow (or push
to main) to build the binary and (re)start enabled instances.

Watch:  journalctl -u 'vk-turn-proxy@udp' -f
        journalctl -u 'vk-turn-proxy@vless' -f
MSG

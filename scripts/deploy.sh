#!/bin/bash
# Atomically replace /opt/vk-turn-proxy/{server,captcha-service} with the
# freshly-built binaries and restart any enabled vk-turn-proxy@* instance
# plus captcha-service.service.
# Intended to be invoked from the self-hosted GitHub Actions runner.
set -euo pipefail

NEW_SERVER="${1:-./dist/server}"
NEW_CAPTCHA="${2:-./dist/captcha-service}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vk-turn-proxy}"
SERVER_BINARY="${INSTALL_DIR}/server"
CAPTCHA_BINARY="${INSTALL_DIR}/captcha-service"

swap_binary() {
    local src="$1" dst="$2"
    if [ ! -f "$src" ]; then
        echo "deploy.sh: binary not found at $src — skipping" >&2
        return 1
    fi
    sudo /usr/bin/install -m 0755 -o root -g root "$src" "${dst}.new"
    sudo /bin/mv -f "${dst}.new" "$dst"
    echo "Installed ${dst}."
    return 0
}

swap_binary "$NEW_SERVER" "$SERVER_BINARY" || true
swap_binary "$NEW_CAPTCHA" "$CAPTCHA_BINARY" || true

restarted=0
for instance in udp vless; do
    unit="vk-turn-proxy@${instance}.service"
    if sudo /bin/systemctl is-enabled "$unit" >/dev/null 2>&1; then
        echo "Restarting $unit..."
        sudo /bin/systemctl restart "$unit"
        restarted=$((restarted + 1))
    fi
done

if sudo /bin/systemctl is-enabled captcha-service.service >/dev/null 2>&1; then
    echo "Restarting captcha-service.service..."
    sudo /bin/systemctl restart captcha-service.service
    restarted=$((restarted + 1))
fi

if [ "$restarted" -eq 0 ]; then
    echo "Note: no enabled unit found (vk-turn-proxy@* / captcha-service)."
    echo "      Run scripts/install.sh first."
fi

echo "Deploy complete."

#!/bin/bash
# Atomically replace /opt/vk-turn-proxy/server with a freshly-built binary
# and restart any enabled vk-turn-proxy@* instance.
# Intended to be invoked from the self-hosted GitHub Actions runner.
set -euo pipefail

NEW_BINARY="${1:-./dist/server}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vk-turn-proxy}"
BINARY="${INSTALL_DIR}/server"

if [ ! -f "$NEW_BINARY" ]; then
    echo "deploy.sh: binary not found at $NEW_BINARY" >&2
    exit 1
fi

sudo /usr/bin/install -m 0755 -o root -g root "$NEW_BINARY" "${BINARY}.new"
sudo /bin/mv -f "${BINARY}.new" "$BINARY"

restarted=0
for instance in udp vless; do
    unit="vk-turn-proxy@${instance}.service"
    if sudo /bin/systemctl is-enabled "$unit" >/dev/null 2>&1; then
        echo "Restarting $unit..."
        sudo /bin/systemctl restart "$unit"
        restarted=$((restarted + 1))
    fi
done

if [ "$restarted" -eq 0 ]; then
    echo "Note: no enabled vk-turn-proxy@* instance found."
    echo "      Run scripts/install.sh and 'systemctl enable --now vk-turn-proxy@udp.service'."
fi

echo "Deploy complete."

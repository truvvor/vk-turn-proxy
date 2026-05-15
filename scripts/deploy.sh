#!/bin/bash
# Atomically replace /opt/vk-turn-proxy/{server,captcha-service} with the
# freshly-built binaries and restart only the units whose binary changed.
# Either positional arg can be empty to skip that binary.
set -euo pipefail

NEW_SERVER="${1-}"
NEW_CAPTCHA="${2-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vk-turn-proxy}"
SERVER_BINARY="${INSTALL_DIR}/server"
CAPTCHA_BINARY="${INSTALL_DIR}/captcha-service"

swapped_server=0
swapped_captcha=0

if [ -n "$NEW_SERVER" ] && [ -f "$NEW_SERVER" ]; then
    sudo /usr/bin/install -m 0755 -o root -g root "$NEW_SERVER" "${SERVER_BINARY}.new"
    sudo /bin/mv -f "${SERVER_BINARY}.new" "$SERVER_BINARY"
    echo "Installed ${SERVER_BINARY}."
    swapped_server=1
elif [ -n "$NEW_SERVER" ]; then
    echo "deploy.sh: server binary not found at $NEW_SERVER" >&2
fi

if [ -n "$NEW_CAPTCHA" ] && [ -f "$NEW_CAPTCHA" ]; then
    sudo /usr/bin/install -m 0755 -o root -g root "$NEW_CAPTCHA" "${CAPTCHA_BINARY}.new"
    sudo /bin/mv -f "${CAPTCHA_BINARY}.new" "$CAPTCHA_BINARY"
    echo "Installed ${CAPTCHA_BINARY}."
    swapped_captcha=1
elif [ -n "$NEW_CAPTCHA" ]; then
    echo "deploy.sh: captcha-service binary not found at $NEW_CAPTCHA" >&2
fi

restarted=0
if [ "$swapped_server" -eq 1 ]; then
    for instance in udp vless; do
        unit="vk-turn-proxy@${instance}.service"
        if sudo /bin/systemctl is-enabled "$unit" >/dev/null 2>&1; then
            echo "Restarting $unit..."
            sudo /bin/systemctl restart "$unit"
            restarted=$((restarted + 1))
        fi
    done
fi

if [ "$swapped_captcha" -eq 1 ]; then
    if sudo /bin/systemctl is-enabled captcha-service.service >/dev/null 2>&1; then
        echo "Restarting captcha-service.service..."
        sudo /bin/systemctl restart captcha-service.service
        restarted=$((restarted + 1))
    fi
fi

echo "Deploy complete (binaries swapped: server=$swapped_server captcha=$swapped_captcha; units restarted: $restarted)."

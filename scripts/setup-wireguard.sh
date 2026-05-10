#!/bin/bash
# Idempotent WireGuard server setup. Designed to be run from the
# self-hosted GitHub Actions runner ("Setup WireGuard" workflow).
#
# What it does:
#   - apt-installs wireguard / wireguard-tools if missing
#   - generates server + client keypairs in /etc/wireguard (only once)
#   - writes /etc/wireguard/wg0.conf
#   - enables IPv4 forwarding via /etc/sysctl.d/99-wireguard.conf
#   - sets up MASQUERADE + FORWARD rules through wg-quick PostUp/PostDown
#   - enables and starts wg-quick@wg0
#
# What it does NOT do:
#   - touch /etc/xray, /etc/nginx, /etc/sudoers or any unrelated services
#   - rotate existing keys (re-runs reuse what's already in /etc/wireguard)
#
# Tunables (env vars):
#   SUBNET       (default 10.13.13.0/24)
#   SERVER_IP    (default 10.13.13.1/24)
#   CLIENT_IP    (default 10.13.13.2/32)
#   LISTEN_PORT  (default 51820)
#   EXT_IF       (default auto-detected via `ip route get 1.1.1.1`)

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "setup-wireguard.sh must run as root (try: sudo $0)" >&2
    exit 1
fi

SUBNET="${SUBNET:-10.13.13.0/24}"
SERVER_IP="${SERVER_IP:-10.13.13.1/24}"
CLIENT_IP="${CLIENT_IP:-10.13.13.2/32}"
LISTEN_PORT="${LISTEN_PORT:-51820}"
WG_DIR=/etc/wireguard

if [ -z "${EXT_IF:-}" ]; then
    EXT_IF="$(ip route get 1.1.1.1 2>/dev/null \
              | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
fi
[ -z "$EXT_IF" ] && { echo "Cannot detect external interface; set EXT_IF=" >&2; exit 1; }

echo "==> External interface: $EXT_IF"
echo "==> Subnet:             $SUBNET (server $SERVER_IP, client $CLIENT_IP)"
echo "==> ListenPort:         UDP/$LISTEN_PORT"

# Refuse to clobber if some other service already listens on the chosen port
# AND it's not our wg0 (i.e., re-runs are fine).
if ss -ulnH "sport = :$LISTEN_PORT" 2>/dev/null | grep -q .; then
    if ! ip link show wg0 >/dev/null 2>&1; then
        echo "ERROR: UDP/$LISTEN_PORT is already in use by something other than wg0:" >&2
        ss -ulnp "sport = :$LISTEN_PORT" >&2
        echo "Pick a different LISTEN_PORT and re-run." >&2
        exit 1
    fi
fi

# ---- Packages ----
if ! command -v wg >/dev/null 2>&1; then
    echo "==> Installing wireguard packages"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools
fi

mkdir -p "$WG_DIR"
chmod 0700 "$WG_DIR"
cd "$WG_DIR"
umask 077

# ---- Keys (idempotent) ----
gen_keypair() {
    local name="$1"
    if [ ! -f "${name}_private.key" ]; then
        wg genkey > "${name}_private.key"
        wg pubkey < "${name}_private.key" > "${name}_public.key"
        chmod 0600 "${name}_private.key" "${name}_public.key"
        echo "Generated keypair: ${name}"
    fi
}
gen_keypair server
gen_keypair client

SERVER_PRIV="$(cat server_private.key)"
CLIENT_PUB="$(cat client_public.key)"

# ---- Server config ----
cat > wg0.conf <<EOF
[Interface]
Address = ${SERVER_IP}
ListenPort = ${LISTEN_PORT}
PrivateKey = ${SERVER_PRIV}
PostUp   = iptables -t nat -A POSTROUTING -s ${SUBNET} -o ${EXT_IF} -j MASQUERADE
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp   = iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${SUBNET} -o ${EXT_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT

[Peer]
# Single client peer
PublicKey = ${CLIENT_PUB}
AllowedIPs = ${CLIENT_IP}
EOF
chmod 0600 wg0.conf

# ---- IPv4 forwarding ----
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
sysctl --system >/dev/null

# ---- Service ----
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl restart wg-quick@wg0
sleep 1

if ! systemctl is-active --quiet wg-quick@wg0; then
    echo "ERROR: wg-quick@wg0 failed to start. Recent logs:" >&2
    journalctl -u wg-quick@wg0 -n 40 --no-pager >&2
    exit 1
fi

echo
echo "==> wg show"
wg show
echo

echo "Done. Next: run the Deploy workflow — bootstrap will pick up WireGuard"
echo "and add a vk-turn-proxy@udp instance proxying to 127.0.0.1:${LISTEN_PORT}."

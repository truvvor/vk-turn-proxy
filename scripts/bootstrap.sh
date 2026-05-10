#!/bin/bash
# One-shot bootstrap on the deploy server.
# Detects WireGuard / Xray on the host, picks a free UDP LISTEN port, runs
# install.sh with those values, and writes the runner sudoers rule.
# Run once as root. Idempotent: safe to re-run.
#
#   sudo ./scripts/bootstrap.sh           # detect, then install
#   sudo ./scripts/bootstrap.sh --dry-run # only print what would be done

set -euo pipefail

DRY_RUN=0
case "${1:-}" in
    --dry-run|-n) DRY_RUN=1 ;;
    "") ;;
    *) echo "Unknown arg '$1'. Use --dry-run or no args." >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "bootstrap.sh must run as root (try: sudo $0)" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "------------------------------------------------------------"; }

hr; say "Inventory"; hr

# ---------------- WireGuard ----------------
WG_PORT=""
WG_SOURCE=""
if compgen -G "/etc/wireguard/*.conf" >/dev/null; then
    WG_PORT="$(grep -hE '^\s*ListenPort' /etc/wireguard/*.conf 2>/dev/null \
               | head -1 | awk -F'=' '{print $2}' | tr -d '[:space:]')" || true
    [ -n "$WG_PORT" ] && WG_SOURCE="/etc/wireguard/*.conf"
fi
if [ -z "$WG_PORT" ] && command -v wg >/dev/null 2>&1; then
    WG_PORT="$(wg show 2>/dev/null | awk '/listening port/{print $3; exit}')" || true
    [ -n "$WG_PORT" ] && WG_SOURCE="wg show"
fi
if [ -n "$WG_PORT" ]; then
    say "WireGuard:    detected on UDP port ${WG_PORT}  (source: ${WG_SOURCE})"
else
    say "WireGuard:    NOT detected"
fi

# ---------------- Xray ----------------
XRAY_PORT=""
XRAY_SOURCE=""
XRAY_CONFIG=""
for candidate in /usr/local/etc/xray/config.json /etc/xray/config.json; do
    if [ -r "$candidate" ]; then
        XRAY_CONFIG="$candidate"
        break
    fi
done
if [ -n "$XRAY_CONFIG" ]; then
    if command -v jq >/dev/null 2>&1; then
        XRAY_PORT="$(jq -r '.inbounds[0].port // empty' "$XRAY_CONFIG" 2>/dev/null)"
        XRAY_SOURCE="$XRAY_CONFIG (jq)"
    else
        XRAY_PORT="$(grep -oE '"port"\s*:\s*[0-9]+' "$XRAY_CONFIG" \
                     | head -1 | grep -oE '[0-9]+')" || true
        XRAY_SOURCE="$XRAY_CONFIG (grep)"
    fi
fi
if systemctl is-active --quiet xray 2>/dev/null; then
    XRAY_ACTIVE=yes
else
    XRAY_ACTIVE=no
fi
if [ -n "$XRAY_PORT" ]; then
    say "Xray:         active=${XRAY_ACTIVE}, port ${XRAY_PORT}  (source: ${XRAY_SOURCE})"
elif [ "$XRAY_ACTIVE" = yes ]; then
    say "Xray:         active=yes, port unknown (no readable config)"
else
    say "Xray:         NOT detected"
fi

# ---------------- Free LISTEN port for our proxy ----------------
port_busy() { ss -uln 2>/dev/null | awk 'NR>1{print $5}' | grep -qE "(:|\])${1}$"; }

PROXY_PORT=""
for candidate in 56000 56010 56020 56100 56200 57000; do
    if ! port_busy "$candidate"; then
        PROXY_PORT="$candidate"
        break
    fi
done
if [ -z "$PROXY_PORT" ]; then
    say "ERROR: no free UDP port found in 56000-57000 range." >&2
    exit 1
fi
say "vk-turn-proxy will LISTEN on UDP ${PROXY_PORT}  (free, won't collide)"

# ---------------- Runner user ----------------
RUNNER_PID="$(pgrep -f Runner.Listener | head -1 || true)"
if [ -n "$RUNNER_PID" ]; then
    RUNNER_USER="$(ps -o user= -p "$RUNNER_PID" | tr -d '[:space:]')"
    say "Runner user:  ${RUNNER_USER}  (pid ${RUNNER_PID})"
else
    RUNNER_USER=""
    say "Runner user:  NOT FOUND (Runner.Listener process is not running)"
fi

# ---------------- Public IP ----------------
PUBLIC_IP="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null \
            || curl -fsS --max-time 3 https://ifconfig.me 2>/dev/null \
            || echo '<your-server-ip>')"
say "Public IP:    ${PUBLIC_IP}"

hr; say "Plan"; hr

UDP_CONNECT="127.0.0.1:${WG_PORT:-51820}"
say "  install.sh will create:"
say "    /etc/vk-turn-proxy/udp.env    LISTEN=0.0.0.0:${PROXY_PORT}  CONNECT=${UDP_CONNECT}"
if [ -n "$XRAY_PORT" ]; then
    say "    /etc/vk-turn-proxy/vless.env  LISTEN=0.0.0.0:$((PROXY_PORT + 1))  CONNECT=127.0.0.1:${XRAY_PORT}"
fi
say "  systemctl will:"
say "    daemon-reload, enable vk-turn-proxy@udp.service${XRAY_PORT:+, enable vk-turn-proxy@vless.service}"
if [ -n "$RUNNER_USER" ]; then
    say "  sudoers will be installed at /etc/sudoers.d/vk-turn-proxy-runner for user '${RUNNER_USER}'"
fi
say "  Existing wireguard / xray configurations will NOT be touched."
say ""
say "  Connection URL after deploy:  ${PUBLIC_IP}:${PROXY_PORT}/udp"

if [ "$DRY_RUN" -eq 1 ]; then
    hr; say "Dry-run: nothing changed."; hr
    exit 0
fi

hr; say "Applying"; hr

INSTALL_ENV=(UDP_CONNECT="$UDP_CONNECT" UDP_LISTEN="0.0.0.0:${PROXY_PORT}")
if [ -n "$XRAY_PORT" ]; then
    INSTALL_ENV+=(VLESS_CONNECT="127.0.0.1:${XRAY_PORT}" VLESS_LISTEN="0.0.0.0:$((PROXY_PORT + 1))")
fi
env "${INSTALL_ENV[@]}" "$REPO_DIR/scripts/install.sh"

if [ -n "$RUNNER_USER" ]; then
    SUDOERS=/etc/sudoers.d/vk-turn-proxy-runner
    install -m 0440 -o root -g root "$REPO_DIR/deploy/sudoers.example" "$SUDOERS"
    sed -i "s/github-runner/${RUNNER_USER}/g" "$SUDOERS"
    if ! visudo -cf "$SUDOERS" >/dev/null; then
        say "ERROR: visudo refused $SUDOERS" >&2
        rm -f "$SUDOERS"
        exit 1
    fi
    say "Installed ${SUDOERS} (allowed user: ${RUNNER_USER})"
fi

hr
say "Bootstrap complete."
say ""
say "Next:"
say "  1. GitHub → Actions → Deploy → Run workflow"
say "     (use ref 'claude/setup-daemon-deployment-e19Al' until merged)"
say "  2. Open UDP/${PROXY_PORT} in your firewall / cloud security group."
say ""
say "Connection URL:  ${PUBLIC_IP}:${PROXY_PORT}/udp"
hr

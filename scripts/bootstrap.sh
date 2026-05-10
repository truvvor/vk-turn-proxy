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
        # Pick the most likely user-facing VLESS inbound, in priority order:
        # 1. vless on 443 (typical Reality / TLS production setup)
        # 2. any vless inbound
        # 3. any inbound on 443
        # 4. first inbound in the file (last-resort guess)
        for sel in \
            '.inbounds[]? | select(.protocol=="vless" and .port==443) | .port' \
            '.inbounds[]? | select(.protocol=="vless") | .port' \
            '.inbounds[]? | select(.port==443) | .port' \
            '.inbounds[0]?.port'; do
            cand="$(jq -r "($sel) // empty" "$XRAY_CONFIG" 2>/dev/null | head -1)"
            if [ -n "$cand" ] && [ "$cand" != "null" ]; then
                XRAY_PORT="$cand"
                XRAY_SOURCE="$XRAY_CONFIG (jq: $sel)"
                break
            fi
        done
    else
        XRAY_PORT="$(grep -oE '"port"\s*:\s*[0-9]+' "$XRAY_CONFIG" \
                     | head -1 | grep -oE '[0-9]+')" || true
        XRAY_SOURCE="$XRAY_CONFIG (grep)"
    fi
fi

# Explicit override via env wins over autodetection.
if [ -n "${XRAY_PORT_OVERRIDE:-}" ]; then
    XRAY_PORT="$XRAY_PORT_OVERRIDE"
    XRAY_SOURCE="env XRAY_PORT_OVERRIDE"
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
# Use ss's `sport` filter directly — parsing columns is fragile because
# `ss -uln` may right-align addresses and the column count differs across
# versions. Returns 0 (busy) iff at least one socket binds the port.
port_busy() {
    [ -n "$(ss -ulnH "sport = :$1" 2>/dev/null)" ]
}

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

INSTALL_ENV=()
PROXY_UDP_PORT=""
PROXY_VLESS_PORT=""

if [ -n "$WG_PORT" ]; then
    PROXY_UDP_PORT="$PROXY_PORT"
    INSTALL_ENV+=(UDP_CONNECT="127.0.0.1:${WG_PORT}" UDP_LISTEN="0.0.0.0:${PROXY_UDP_PORT}")
    say "  vk-turn-proxy@udp:    LISTEN 0.0.0.0:${PROXY_UDP_PORT}  CONNECT 127.0.0.1:${WG_PORT}"
else
    say "  vk-turn-proxy@udp:    SKIPPED (WireGuard not detected on this host)"
fi

if [ -n "$XRAY_PORT" ]; then
    if [ -n "$PROXY_UDP_PORT" ]; then
        PROXY_VLESS_PORT=$((PROXY_UDP_PORT + 1))
    else
        PROXY_VLESS_PORT="$PROXY_PORT"
    fi
    INSTALL_ENV+=(VLESS_CONNECT="127.0.0.1:${XRAY_PORT}" VLESS_LISTEN="0.0.0.0:${PROXY_VLESS_PORT}")
    say "  vk-turn-proxy@vless:  LISTEN 0.0.0.0:${PROXY_VLESS_PORT}  CONNECT 127.0.0.1:${XRAY_PORT}"
else
    say "  vk-turn-proxy@vless:  SKIPPED (Xray not detected on this host)"
fi

if [ "${#INSTALL_ENV[@]}" -eq 0 ]; then
    say ""
    say "ERROR: neither WireGuard nor Xray detected. Nothing to do." >&2
    exit 1
fi

# Sudoers: only install our narrow rule when the runner DOESN'T already have
# broader sudo coverage. If sudo -n -l already shows (ALL) NOPASSWD: ALL or a
# pre-existing NOPASSWD on the commands deploy.sh needs, leave it alone.
WANT_SUDOERS=1
if [ -n "$RUNNER_USER" ]; then
    if sudo -n -l -U "$RUNNER_USER" 2>/dev/null | grep -qE 'NOPASSWD:\s*ALL'; then
        WANT_SUDOERS=0
        say "  sudoers:              SKIPPED (user '${RUNNER_USER}' already has NOPASSWD ALL)"
    else
        say "  sudoers:              install /etc/sudoers.d/vk-turn-proxy-runner for '${RUNNER_USER}'"
    fi
else
    WANT_SUDOERS=0
    say "  sudoers:              SKIPPED (Runner.Listener process not found)"
fi

say ""
say "  Existing wireguard / xray configurations will NOT be touched."
say ""
[ -n "$PROXY_UDP_PORT" ]   && say "  WireGuard URL:  ${PUBLIC_IP}:${PROXY_UDP_PORT}/udp"
[ -n "$PROXY_VLESS_PORT" ] && say "  VLESS URL:      ${PUBLIC_IP}:${PROXY_VLESS_PORT}/udp"

if [ "$DRY_RUN" -eq 1 ]; then
    hr; say "Dry-run: nothing changed."; hr
    exit 0
fi

hr; say "Applying"; hr

env "${INSTALL_ENV[@]}" "$REPO_DIR/scripts/install.sh"

if [ "$WANT_SUDOERS" -eq 1 ]; then
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
say "Next:  GitHub → Actions → Deploy → Run workflow."
say "       Open the LISTEN port(s) in the cloud firewall / security group."
say ""
[ -n "$PROXY_UDP_PORT" ]   && say "WireGuard URL:  ${PUBLIC_IP}:${PROXY_UDP_PORT}/udp"
[ -n "$PROXY_VLESS_PORT" ] && say "VLESS URL:      ${PUBLIC_IP}:${PROXY_VLESS_PORT}/udp"
hr

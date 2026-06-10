#!/usr/bin/env bash
# install-warp.sh — provision a Cloudflare WARP WireGuard tunnel for
# captcha-service's VK-bound outbound traffic. Idempotent: re-runs on
# a node where wgcf is already up are 1-second no-ops.
#
# Why: VK rate-limits captcha endpoints by source IP. The host's
# default egress (eth0) hits that limit fast across the cluster.
# Pinning captcha-service's sockets to a WARP interface routes those
# requests through Cloudflare's edge IP space, which VK doesn't
# rate-limit anywhere near as hard (it's shared with millions of
# legitimate users).
#
# Architecture:
#   1. wgcf register   → free WARP account, stored in wgcf-account.toml
#   2. wgcf generate   → /etc/wireguard/wgcf.conf
#   3. patch Table=off so the tunnel doesn't grab the host default
#      route (we ONLY want captcha-service's specific sockets to
#      egress via WARP, NOT every other service on the box)
#   4. systemctl enable --now wg-quick@wgcf
#   5. captcha-service reads WARP_INTERFACE=wgcf at startup and
#      installs an SO_BINDTODEVICE control hook on every outbound
#      net.Dialer
#
# Run as root, on each cluster node, before captcha-service first
# starts (deploy-cluster.yml handles the wiring).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install-warp.sh must run as root (try: sudo $0)" >&2
    exit 1
fi

WG_NAME="${WG_NAME:-wgcf}"
WG_CONF="/etc/wireguard/${WG_NAME}.conf"
WGCF_DIR="/opt/wgcf"
WGCF_BIN="${WGCF_DIR}/wgcf"
WGCF_ACCOUNT="${WGCF_DIR}/wgcf-account.toml"
WGCF_VERSION="${WGCF_VERSION:-2.2.27}"

# Short-circuit if WARP is already up.
if [ -f "$WG_CONF" ] && systemctl is-active --quiet "wg-quick@${WG_NAME}"; then
    echo "WARP already up via ${WG_NAME}, leaving alone."
    wg show "${WG_NAME}" 2>&1 || true
    exit 0
fi

# Prereqs. wireguard-tools brings in wg + wg-quick; resolvconf is
# what wg-quick uses to manage /etc/resolv.conf for the interface
# (we don't actually want WARP DNS but wg-quick complains if the tool
# is missing).
DEBIAN_FRONTEND=noninteractive apt-get update -q || true
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    wireguard-tools iptables resolvconf curl ca-certificates

# Install wgcf binary (https://github.com/ViRb3/wgcf).
if ! [ -x "$WGCF_BIN" ]; then
    mkdir -p "$WGCF_DIR"
    arch="$(uname -m)"
    case "$arch" in
        x86_64)  arch=amd64 ;;
        aarch64) arch=arm64 ;;
        *) echo "install-warp.sh: unsupported arch '$arch'" >&2; exit 1 ;;
    esac
    curl -fsSL --retry 5 \
        "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${arch}" \
        -o "$WGCF_BIN"
    chmod +x "$WGCF_BIN"
    echo "Installed wgcf ${WGCF_VERSION} at ${WGCF_BIN}"
fi

# Register a Cloudflare WARP account if we don't already have one.
# --accept-tos handles the EULA prompt itself; an earlier version of
# this script piped `yes` in as belt-and-suspenders which races wgcf's
# stdin close → SIGPIPE 141 → set -euo pipefail aborts the script even
# though the register itself succeeded. The account toml gets written
# before that failure, so the wgcf is idempotent enough that a re-run
# skips this step anyway — but no point making the operator re-run.
if ! [ -f "$WGCF_ACCOUNT" ]; then
    cd "$WGCF_DIR"
    "$WGCF_BIN" register --accept-tos
fi

# Generate the WireGuard config from the registered account if it's
# not on disk yet. The output is owned by the user wgcf ran as
# (here: root); chmod 0600 keeps the private key off other accounts.
if ! [ -f "$WG_CONF" ]; then
    cd "$WGCF_DIR"
    "$WGCF_BIN" generate -o "$WG_CONF"
    # CRITICAL: prevent WARP from grabbing the default route.
    # Without `Table = off` wg-quick installs WARP as the default
    # exit for the WHOLE host, which breaks the GitHub Actions
    # runner, ssh, and basically every other service.
    # captcha-service's SO_BINDTODEVICE works regardless of the
    # routing table — it pins per-socket, not per-route.
    if ! grep -q '^Table[[:space:]]*=' "$WG_CONF"; then
        sed -i '/^\[Interface\]/a Table = off' "$WG_CONF"
    fi
    chmod 0600 "$WG_CONF"
    echo "Generated ${WG_CONF}"
fi

# Bring the interface up.
systemctl daemon-reload
systemctl enable "wg-quick@${WG_NAME}"
systemctl start "wg-quick@${WG_NAME}"

sleep 1
if ! systemctl is-active --quiet "wg-quick@${WG_NAME}"; then
    echo "install-warp.sh: wg-quick@${WG_NAME} failed to start" >&2
    journalctl -u "wg-quick@${WG_NAME}" -n 40 --no-pager
    exit 1
fi

echo "WARP up via ${WG_NAME}:"
wg show "${WG_NAME}"

# Smoke test: hit Cloudflare's trace endpoint via the WARP iface
# directly. If `warp=on` is in the response we know the tunnel is
# carrying traffic. Best-effort — some hosts ship curl without
# --interface support, don't fail the script over it.
trace="$(curl -fsSL --interface "${WG_NAME}" --max-time 5 \
    https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
if echo "$trace" | grep -q '^warp=on'; then
    echo "smoke test OK: cdn-cgi/trace shows warp=on"
elif [ -n "$trace" ]; then
    echo "smoke test partial — trace returned but no warp=on line:"
    echo "$trace" | head -5
else
    echo "smoke test skipped (curl --interface unavailable or 1.1.1.1 unreachable)"
fi

echo "OK: WARP ready on iface ${WG_NAME}. Set WARP_INTERFACE=${WG_NAME} in captcha-service env."

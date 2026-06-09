#!/usr/bin/env bash
# Sets up chrome-headless-shell + runtime libs on a Debian/Ubuntu cloud server.
# Required by the headless VK-captcha solver (-headless-captcha).
set -euo pipefail
VER="${1:-149.0.7827.55}"   # Chrome-for-Testing version (any recent stable works)
URL="https://storage.googleapis.com/chrome-for-testing-public/${VER}/linux64/chrome-headless-shell-linux64.zip"

sudo DEBIAN_FRONTEND=noninteractive apt-get update -q || true
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  unzip ca-certificates fonts-liberation \
  libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
  libasound2t64 libatspi2.0-0t64 libxshmfence1 libpango-1.0-0 libcairo2

sudo mkdir -p /opt/chs && cd /opt/chs
curl -L --retry 20 -o chs.zip "$URL"
sudo unzip -o chs.zip >/dev/null
sudo chmod +x chrome-headless-shell-linux64/chrome-headless-shell
sudo ln -sf /opt/chs/chrome-headless-shell-linux64/chrome-headless-shell /usr/local/bin/chrome-headless-shell
/usr/local/bin/chrome-headless-shell --version
echo "OK: chrome-headless-shell ready at /usr/local/bin/chrome-headless-shell"

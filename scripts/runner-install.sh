#!/bin/bash
# Register and start a GitHub Actions self-hosted runner for this repo.
# Run once on the deployment server, as root.
#
# Required env vars:
#   RUNNER_URL    Repository URL, e.g. https://github.com/truvvor/vk-turn-proxy
#   RUNNER_TOKEN  One-time registration token from
#                 Settings → Actions → Runners → New self-hosted runner
#
# Optional env vars:
#   RUNNER_USER     System user to run the runner as (default: github-runner)
#   RUNNER_HOME     Install path (default: /opt/actions-runner)
#   RUNNER_NAME     Runner name (default: hostname)
#   RUNNER_LABELS   Extra labels (always includes self-hosted,linux,x64)
#   RUNNER_VERSION  Runner version (default: 2.321.0)
#
# After this script finishes, also install the sudoers rule so the runner
# can deploy without a password prompt:
#
#   sudo install -m 0440 -o root -g root \
#       deploy/sudoers.example /etc/sudoers.d/vk-turn-proxy-runner
#   sudo sed -i "s/github-runner/${RUNNER_USER:-github-runner}/g" \
#       /etc/sudoers.d/vk-turn-proxy-runner
#   sudo visudo -cf /etc/sudoers.d/vk-turn-proxy-runner

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "runner-install.sh must be run as root" >&2
    exit 1
fi

: "${RUNNER_URL:?set RUNNER_URL=https://github.com/<owner>/<repo>}"
: "${RUNNER_TOKEN:?set RUNNER_TOKEN=<one-time token from GitHub>}"

RUNNER_USER="${RUNNER_USER:-github-runner}"
RUNNER_HOME="${RUNNER_HOME:-/opt/actions-runner}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname)}"
RUNNER_LABELS="${RUNNER_LABELS:-}"
RUNNER_VERSION="${RUNNER_VERSION:-2.321.0}"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GH_ARCH=x64 ;;
    aarch64) GH_ARCH=arm64 ;;
    *) echo "Unsupported arch $ARCH" >&2; exit 1 ;;
esac

LABELS="self-hosted,linux,${GH_ARCH}"
if [ -n "$RUNNER_LABELS" ]; then
    LABELS="${LABELS},${RUNNER_LABELS}"
fi

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    echo "==> Creating system user $RUNNER_USER"
    useradd --system --create-home --home-dir "/home/$RUNNER_USER" --shell /bin/bash "$RUNNER_USER"
fi

install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"

if [ ! -x "$RUNNER_HOME/config.sh" ]; then
    echo "==> Downloading actions-runner v${RUNNER_VERSION}"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${GH_ARCH}-${RUNNER_VERSION}.tar.gz"
    curl -fsSL "$URL" -o "$TMP/runner.tgz"
    sudo -u "$RUNNER_USER" tar -xzf "$TMP/runner.tgz" -C "$RUNNER_HOME"
fi

if [ -e "$RUNNER_HOME/.runner" ]; then
    echo "==> Runner already configured at $RUNNER_HOME (.runner present); skipping configure"
else
    echo "==> Configuring runner: name=$RUNNER_NAME labels=$LABELS"
    sudo -u "$RUNNER_USER" "$RUNNER_HOME/config.sh" \
        --unattended \
        --url "$RUNNER_URL" \
        --token "$RUNNER_TOKEN" \
        --name "$RUNNER_NAME" \
        --labels "$LABELS" \
        --work _work \
        --replace
fi

echo "==> Installing as systemd service"
( cd "$RUNNER_HOME" && ./svc.sh install "$RUNNER_USER" && ./svc.sh start )

echo
echo "Runner '$RUNNER_NAME' is up. Verify in GitHub:"
echo "    ${RUNNER_URL}/settings/actions/runners"
echo
echo "Next: install the sudoers rule (see top of this script) so the workflow"
echo "can run scripts/deploy.sh without a password prompt."

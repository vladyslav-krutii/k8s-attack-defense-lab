#!/usr/bin/env bash
# Installs a pinned kubectl into ~/.local/bin (no sudo needed).
#
# Why: in Kali under WSL2, /usr/local/bin/kubectl is a symlink into Docker
# Desktop's own tools. It changes version whenever Desktop updates, and it
# disappears while Desktop is stopped. The lab should not depend on that.
# ~/.local/bin comes first in PATH (see ~/.profile), so this copy wins.
#
# Version skew: kubectl is supported within +/-1 minor version of the API
# server. Pinning it to the cluster's exact version (kindest/node v1.36.4)
# removes the question entirely.
set -euo pipefail

KUBECTL_VERSION=${KUBECTL_VERSION:-v1.36.4}
ARCH=amd64
DEST=${DEST:-$HOME/.local/bin}
URL=https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$ARCH/kubectl

# Capture first, then match: "cmd | grep -q" under pipefail can fail with
# SIGPIPE when grep exits early, and would wrongly report "not installed".
current=$("$DEST/kubectl" version --client 2>/dev/null || true)
if grep -q "^Client Version: $KUBECTL_VERSION$" <<<"$current"; then
  echo "kubectl $KUBECTL_VERSION already installed: $DEST/kubectl"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading kubectl $KUBECTL_VERSION"
curl -fsSLo "$tmp/kubectl" "$URL"
# The .sha256 file holds only the hash; sha256sum -c expects "<hash>  <file>".
echo "$(curl -fsSL "$URL.sha256")  kubectl" > "$tmp/kubectl.sha256"

echo "==> Verifying SHA-256"
(cd "$tmp" && sha256sum -c kubectl.sha256)

mkdir -p "$DEST"
install -m 0755 "$tmp/kubectl" "$DEST/kubectl"
echo "==> Installed: $("$DEST/kubectl" version --client | head -1) -> $DEST/kubectl"

active=$(command -v kubectl || true)
if [ "$active" != "$DEST/kubectl" ]; then
  echo "NOTE: 'kubectl' still resolves to $active - put $DEST first in PATH"
  echo "      (or open a new login shell: ~/.profile adds it)."
fi

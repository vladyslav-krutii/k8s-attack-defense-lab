#!/usr/bin/env bash
# Installs a pinned Helm release into ~/.local/bin (no sudo needed).
#
# Why not "curl https://.../get-helm-3 | bash"? Piping a remote script into a
# shell runs whatever the server returns at that moment. Here the version is
# pinned and the archive is checked against its published SHA-256 before
# anything is extracted - the same supply-chain hygiene as scenario 6.
# Limitation: the checksum comes from the same host as the archive, so it
# proves integrity (no corruption / tampering in transit), not authenticity.
# Helm also publishes GPG signatures (.asc) for that.
set -euo pipefail

HELM_VERSION=${HELM_VERSION:-v4.3.2}
ARCH=linux-amd64
DEST=${DEST:-$HOME/.local/bin}
BASE=https://get.helm.sh
TARBALL=helm-$HELM_VERSION-$ARCH.tar.gz

if command -v helm >/dev/null && helm version --template '{{.Version}}' | grep -qx "$HELM_VERSION"; then
  echo "helm $HELM_VERSION already installed: $(command -v helm)"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading $TARBALL"
curl -fsSLo "$tmp/$TARBALL" "$BASE/$TARBALL"
curl -fsSLo "$tmp/$TARBALL.sha256sum" "$BASE/$TARBALL.sha256sum"

echo "==> Verifying SHA-256"
(cd "$tmp" && sha256sum -c "$TARBALL.sha256sum")

tar -xzf "$tmp/$TARBALL" -C "$tmp"
mkdir -p "$DEST"
install -m 0755 "$tmp/$ARCH/helm" "$DEST/helm"

echo "==> Installed: $("$DEST/helm" version --template '{{.Version}}') -> $DEST/helm"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo "NOTE: add $DEST to PATH" ;;
esac

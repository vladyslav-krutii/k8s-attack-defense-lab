#!/usr/bin/env bash
# Installs a pinned Kyverno CLI into ~/.local/bin (no sudo needed).
# Used for "kyverno test": evaluating policies against sample resources
# offline, without a cluster - the same check CI runs in Phase 6.
#
# The CLI version matches the in-cluster Kyverno (v1.20.0), so tests are
# evaluated by the same engine that enforces the policies.
# Integrity: SHA-256 from the release's checksums.txt. The release also ships
# Sigstore bundles (*.sigstore.json) - verifying those with cosign would add
# authenticity (who built it), not just integrity. See scenario 6.
set -euo pipefail

KYVERNO_VERSION=${KYVERNO_VERSION:-v1.20.0}
DEST=${DEST:-$HOME/.local/bin}
TARBALL=kyverno-cli_${KYVERNO_VERSION}_linux_x86_64.tar.gz
BASE=https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VERSION

# Capture first, then match: "cmd | grep -q" under pipefail can fail with
# SIGPIPE when grep exits early, and would wrongly report "not installed".
current=$("$DEST/kyverno" version 2>/dev/null || true)
if grep -q "^Version: $KYVERNO_VERSION$" <<<"$current"; then
  echo "kyverno CLI $KYVERNO_VERSION already installed: $DEST/kyverno"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading $TARBALL"
curl -fsSLo "$tmp/$TARBALL" "$BASE/$TARBALL"
curl -fsSLo "$tmp/checksums.txt" "$BASE/checksums.txt"

echo "==> Verifying SHA-256"
# checksums.txt lists every asset; check only the one we downloaded.
(cd "$tmp" && grep " $TARBALL\$" checksums.txt | sha256sum -c -)

tar -xzf "$tmp/$TARBALL" -C "$tmp" kyverno
mkdir -p "$DEST"
install -m 0755 "$tmp/kyverno" "$DEST/kyverno"
echo "==> Installed: $(grep '^Version:' <<<"$("$DEST/kyverno" version)") -> $DEST/kyverno"

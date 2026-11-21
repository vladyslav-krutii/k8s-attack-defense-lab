#!/usr/bin/env bash
# Installs the pinned CI tools into ~/.local/bin (no sudo needed):
#   kind, kubeconform, gitleaks, trivy, shellcheck
# The same script runs on a laptop and in GitHub Actions, so "make ci-static"
# behaves the same in both places.
#
# Every download is verified against a SHA-256:
#  - from the release's own checksums file where the project publishes one
#    (kind, kubeconform, gitleaks, trivy);
#  - shellcheck publishes none, so its hash is pinned here (computed once from
#    the GitHub release asset; trust on first use, then it can never change).
# kubectl, helm and the kyverno CLI have their own install-*.sh scripts.
#
# Why not the tools' GitHub Actions (aquasecurity/trivy-action, ...)? Every
# third-party action is code that runs with the job's token. A release
# binary with a verified hash is one artefact, the same one used locally.
set -euo pipefail

KIND_VERSION=v0.33.0
KUBECONFORM_VERSION=v0.8.0
GITLEAKS_VERSION=8.30.1
TRIVY_VERSION=0.76.2
SHELLCHECK_VERSION=v0.11.0
SHELLCHECK_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198

DEST=${DEST:-$HOME/.local/bin}
mkdir -p "$DEST"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# fetch <url> <file>
fetch() { curl -fsSL --retry 3 -o "$tmp/$2" "$1"; }
# verify <file> <checksums file>: the line for <file> must match.
verify() {
  (cd "$tmp" && grep -E "[ *]$1\$" "$2" | sed 's/\*/ /' | sha256sum -c - >/dev/null) \
    || { echo "checksum mismatch for $1" >&2; exit 1; }
}
# have <tool> <version string expected in its version output>
have() { "$DEST/$1" "${@:3}" 2>/dev/null | grep -qF -- "$2"; }

if have kind "kind $KIND_VERSION" version; then echo "kind $KIND_VERSION already installed"; else
  echo "==> kind $KIND_VERSION"
  base=https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION
  fetch "$base/kind-linux-amd64" kind-linux-amd64
  fetch "$base/kind-linux-amd64.sha256sum" kind.sha256
  verify kind-linux-amd64 kind.sha256
  install -m 0755 "$tmp/kind-linux-amd64" "$DEST/kind"
fi

if have kubeconform "${KUBECONFORM_VERSION#v}" -v; then echo "kubeconform $KUBECONFORM_VERSION already installed"; else
  echo "==> kubeconform $KUBECONFORM_VERSION"
  base=https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION
  fetch "$base/kubeconform-linux-amd64.tar.gz" kubeconform-linux-amd64.tar.gz
  fetch "$base/CHECKSUMS" CHECKSUMS
  verify kubeconform-linux-amd64.tar.gz CHECKSUMS
  tar -xzf "$tmp/kubeconform-linux-amd64.tar.gz" -C "$tmp" kubeconform
  install -m 0755 "$tmp/kubeconform" "$DEST/kubeconform"
fi

if have gitleaks "$GITLEAKS_VERSION" version; then echo "gitleaks $GITLEAKS_VERSION already installed"; else
  echo "==> gitleaks $GITLEAKS_VERSION"
  base=https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION
  f=gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz
  fetch "$base/$f" "$f"
  fetch "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks.sums
  verify "$f" gitleaks.sums
  tar -xzf "$tmp/$f" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$DEST/gitleaks"
fi

if have trivy "Version: $TRIVY_VERSION" --version; then echo "trivy $TRIVY_VERSION already installed"; else
  echo "==> trivy $TRIVY_VERSION"
  base=https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION
  f=trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
  fetch "$base/$f" "$f"
  fetch "$base/trivy_${TRIVY_VERSION}_checksums.txt" trivy.sums
  verify "$f" trivy.sums
  tar -xzf "$tmp/$f" -C "$tmp" trivy
  install -m 0755 "$tmp/trivy" "$DEST/trivy"
fi

if have shellcheck "version: ${SHELLCHECK_VERSION#v}" --version; then echo "shellcheck $SHELLCHECK_VERSION already installed"; else
  echo "==> shellcheck $SHELLCHECK_VERSION"
  f=shellcheck-$SHELLCHECK_VERSION.linux.x86_64.tar.xz
  fetch "https://github.com/koalaman/shellcheck/releases/download/$SHELLCHECK_VERSION/$f" "$f"
  echo "$SHELLCHECK_SHA256  $f" > "$tmp/shellcheck.sums"
  verify "$f" shellcheck.sums
  tar -xJf "$tmp/$f" -C "$tmp"
  install -m 0755 "$tmp/shellcheck-$SHELLCHECK_VERSION/shellcheck" "$DEST/shellcheck"
fi

echo "==> Installed in $DEST"

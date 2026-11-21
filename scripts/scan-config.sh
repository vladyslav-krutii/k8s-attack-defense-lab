#!/usr/bin/env bash
# Misconfiguration scan of the rendered overlays with trivy config.
#
#   bash scripts/scan-config.sh [rendered-dir]   (default: renders itself)
#
# The two overlays get opposite gates, like verify-all --expect:
#  - hardened must be CLEAN at MEDIUM and above. Accepted findings are
#    listed, each with a reason, in .trivyignore.yaml.
#  - vulnerable must still have HIGH findings. It is broken on purpose; if
#    the scanner suddenly calls it clean, either the demo lost its
#    misconfigurations or the scanner stopped seeing them. Both are bugs.
#
# Exit code 3 is reserved for "findings" (--exit-code 3), so a trivy error
# (exit 1: no network for the checks bundle, a bad flag) can never pass as
# "vulnerable has findings".
# LOW findings are printed for hardened but do not fail the gate.
set -euo pipefail
cd "$(dirname "$0")/.."

dir=${1:-}
if [ -z "$dir" ]; then
  dir=$(mktemp -d)
  bash scripts/lint-manifests.sh "$dir" >/dev/null
fi
fail=0

echo "==> hardened: no MEDIUM/HIGH/CRITICAL findings allowed"
trivy config --quiet --severity LOW "$dir/k8s-overlays-hardened.yaml" \
  | grep -E '^(Failures|KSV)' | sed 's/^/    info (LOW): /' || true
rc=0
trivy config --quiet --exit-code 3 --severity MEDIUM,HIGH,CRITICAL \
  --ignorefile .trivyignore.yaml "$dir/k8s-overlays-hardened.yaml" || rc=$?
case $rc in
  0) echo "PASS  hardened is clean (accepted: see .trivyignore.yaml)" ;;
  3) echo "FAIL  hardened has findings (above)"; fail=1 ;;
  *) echo "ERROR trivy failed (exit $rc)"; exit 2 ;;
esac

echo "==> vulnerable: HIGH findings expected"
rc=0
out=$(trivy config --quiet --exit-code 3 --severity HIGH,CRITICAL \
  "$dir/k8s-overlays-vulnerable.yaml") || rc=$?
case $rc in
  3) echo "PASS  vulnerable is still vulnerable: $(grep -m1 '^Failures' <<<"$out")"
     grep -E '^KSV' <<<"$out" | sort | uniq -c | sed 's/^/    /' ;;
  0) echo "FAIL  vulnerable has no HIGH findings - the demo or the scanner is broken"; fail=1 ;;
  *) echo "ERROR trivy failed (exit $rc)"; exit 2 ;;
esac

exit $fail

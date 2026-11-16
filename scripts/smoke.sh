#!/usr/bin/env bash
# End-to-end smoke test: writes a note through web -> api -> db and reads it
# back. Runs from INSIDE the web pod, so it exercises the same network path a
# real request takes after it reaches nginx.
#
# This test must pass in the base, vulnerable AND hardened deployments:
# hardening that breaks the application is not a fix.
set -euo pipefail

NS=${NAMESPACE:-demo}
kubectl() { command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" "$@"; }

# 127.0.0.1 rather than "localhost" to avoid an IPv6 lookup inside the pod.
in_web() { kubectl exec -n "$NS" deploy/web -- "$@"; }
URL=http://127.0.0.1:8080

MARKER="smoke-$(date +%s)"

echo "==> web serves the static page"
in_web wget -q -T 5 -O - "$URL/" | grep -q "<h1>Notes</h1>"
echo "PASS"

echo "==> POST a note through web -> api -> db"
in_web wget -q -T 5 -O - \
  --header "Content-Type: application/json" \
  --post-data "{\"text\":\"$MARKER\"}" \
  "$URL/api/notes" | grep -q "$MARKER"
echo "PASS"

echo "==> GET the note back"
in_web wget -q -T 5 -O - "$URL/api/notes" | grep -q "$MARKER"
echo "PASS"

echo
echo "Application works end to end."

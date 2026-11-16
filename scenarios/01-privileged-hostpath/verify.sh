#!/usr/bin/env bash
# Scenario 1 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - the web container can read the node's filesystem
#   1 BLOCKED      - it cannot
#   2 INCONCLUSIVE - the test could not run
#
# The signal: /host/etc/hostname inside the container equals the name of the
# node the pod runs on. A pod's own /etc/hostname is the POD name, so a match
# can only come from the node's filesystem.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

require_web || verdict "$INCONCLUSIVE" "web deployment not ready"

pod=$(in_web cat /etc/hostname 2>/dev/null) \
  || verdict "$INCONCLUSIVE" "cannot exec into the web container"
node=$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}' 2>/dev/null)
[ -n "$node" ] || verdict "$INCONCLUSIVE" "cannot determine node of pod $pod"

seen=$(in_web cat /host/etc/hostname 2>/dev/null || true)
if [ "$seen" = "$node" ]; then
  verdict "$EXPLOITABLE" "web pod $pod reads the filesystem of node $node via /host"
fi
verdict "$BLOCKED" "web pod $pod has no access to the filesystem of node $node"

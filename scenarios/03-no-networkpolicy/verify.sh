#!/usr/bin/env bash
# Scenario 3 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - web opens a TCP connection to db:5432
#   1 BLOCKED      - it cannot, while the legitimate web -> api path still works
#   2 INCONCLUSIVE - the test could not run, or web -> api is broken too
#
# The control check matters: if web cannot reach api either (DNS blocked,
# api down, policy too strict), a failed connection to db proves nothing.
# "Blocked" only counts when the allowed path is demonstrably working.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

require_web || verdict "$INCONCLUSIVE" "web deployment not ready"

if ! in_web wget -q -T 3 -O /dev/null http://api:3000/healthz 2>/dev/null; then
  verdict "$INCONCLUSIVE" "control check failed: web cannot reach api:3000"
fi

if in_web nc -z -w 3 db 5432 2>/dev/null; then
  verdict "$EXPLOITABLE" "web reaches db:5432 directly (api bypassed)"
fi
verdict "$BLOCKED" "web -> db:5432 refused while web -> api:3000 works"

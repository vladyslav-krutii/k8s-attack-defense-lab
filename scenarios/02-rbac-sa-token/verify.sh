#!/usr/bin/env bash
# Scenario 2 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - from inside web, the mounted token can read a Secret
#   1 BLOCKED      - no token mounted, API denies (403), or API unreachable
#   2 INCONCLUSIVE - the test could not run
#
# It tests the real attack path from INSIDE the pod rather than
# "kubectl auth can-i" from outside: RBAC could be wrong while the token is
# simply not mounted, or the other way round. Only the combination matters.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

require_web || verdict "$INCONCLUSIVE" "web deployment not ready"
in_web sh -c 'command -v curl' >/dev/null 2>&1 \
  || verdict "$INCONCLUSIVE" "curl not available in the web container"

SA=/var/run/secrets/kubernetes.io/serviceaccount
if ! in_web test -r "$SA/token" 2>/dev/null; then
  verdict "$BLOCKED" "no service account token mounted in web"
fi

# -w prints only the HTTP status; 000 means no connection at all.
code=$(in_web sh -c '
  curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
       --cacert "$1/ca.crt" -H "Authorization: Bearer $(cat "$1/token")" \
       "https://kubernetes.default.svc/api/v1/namespaces/$2/secrets/db-credentials"
' sh "$SA" "$NS" 2>/dev/null)

case $code in
  200) verdict "$EXPLOITABLE" "web's token can read secret db-credentials (HTTP 200)" ;;
  401|403) verdict "$BLOCKED" "API server denied the request (HTTP $code)" ;;
  000) verdict "$BLOCKED" "API server not reachable from web (network policy?)" ;;
  *) verdict "$INCONCLUSIVE" "unexpected HTTP status '$code'" ;;
esac

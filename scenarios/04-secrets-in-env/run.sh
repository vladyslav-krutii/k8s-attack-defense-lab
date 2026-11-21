#!/usr/bin/env bash
# Scenario 4 demo: where does the database password end up when it is passed
# as an environment variable (from a ConfigMap or a Secret)?
#  - a developer with the read-only "view" role (no Secrets!) reads it;
#  - every process in the container has it in its environment.
# Read-only: nothing is changed. Values are always printed masked.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

echo "Scenario 4: credentials in env vars / ConfigMap  (overlay: $(overlay))"
require_web
kubectl -n "$NS" rollout status deploy/api deploy/db --timeout=60s >/dev/null

# Identity with only the built-in "view" role (k8s/base/rbac-developers.yaml).
VIEWER=(--as=lab-developer --as-group=lab:developers)
CRED_RE='(passw(or)?d|secret|token|api_?key|private_?key|credential)'
# Env var names are upper case by convention; matching them case-sensitively
# keeps e.g. "TokenExpirationSeconds" in describe output from matching.
ENV_RE='(PASSW(OR)?D|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)'

# "NAME=value" lines -> NAME=abc*** (n chars); *_FILE values are paths, shown.
mask() {
  awk '{ i = index($0, "="); k = substr($0, 1, i - 1); v = substr($0, i + 1)
         if (k ~ /_FILE$/) print "    " k "=" v "   (a path, not the secret)"
         else print "    " k "=" substr(v, 1, 3) "***  (" length(v) " characters)" }'
}

step "A developer with the 'view' role may not read Secrets"
info "kubectl auth can-i get secrets: $(kubectl auth can-i get secrets -n "$NS" "${VIEWER[@]}" || true)"

step "...but 'view' reads every ConfigMap - any credential-like keys?"
# Single quotes on purpose: $n, $k, $v are go-template variables.
# shellcheck disable=SC2016
found=$(kubectl -n "$NS" get configmaps "${VIEWER[@]}" -o go-template='{{range .items}}{{$n := .metadata.name}}{{range $k, $v := .data}}{{$n}}/{{$k}}={{$v}}{{"\n"}}{{end}}{{end}}' \
  | grep -iE "^[^=/]+/[^=]*${CRED_RE}[^=]*=" || true)
if [ -n "$found" ]; then mask <<<"$found"; else info "none"; fi

step "kubectl describe pod (also 'view') shows where each env var comes from"
kubectl -n "$NS" describe pods -l 'app in (api,db)' "${VIEWER[@]}" \
  | grep -E "^\s+[A-Z_]*${ENV_RE}[A-Z_]*:" | sed 's/^ */    /' || info "no credential-like env vars"

step "Inside the containers: credential-like variables in the environment"
for app in api db; do
  env_hits=$(kubectl -n "$NS" exec "deploy/$app" -- printenv 2>/dev/null \
    | grep -E "^[A-Z_]*${ENV_RE}[A-Z_]*=" || true)
  info "$app:"
  if [ -n "$env_hits" ]; then mask <<<"$env_hits"; else info "    (none)"; fi
done
info "printenv runs as a NEW process: it inherited the variables. So does every"
info "shell, child process, crash reporter and debugger in the container."

step "The running Node process (PID 1 in api) exposes them in /proc/1/environ"
proc_hits=$(kubectl -n "$NS" exec deploy/api -- sh -c 'tr "\0" "\n" < /proc/1/environ' 2>/dev/null \
  | grep -E "^[A-Z_]*${ENV_RE}[A-Z_]*=" || true)
if [ -n "$proc_hits" ]; then mask <<<"$proc_hits"; else info "no credential-like variables"; fi

step "Where the password should live: a read-only file from the Secret"
if kubectl -n "$NS" exec deploy/api -- test -d /etc/db-credentials 2>/dev/null; then
  kubectl -n "$NS" exec deploy/api -- ls -lnL /etc/db-credentials | sed 's/^/    /'
  info "mode 0440, owner root, group = the app's fsGroup; mounted read-only"
else
  info "no file mount in this overlay - the password only exists as env vars"
fi

cat <<'EOF2'

Impact (vulnerable): the password leaks to everyone with "view" (ConfigMaps
and pod specs are not Secrets), and to every process in api and db through
the environment - one "kubectl exec ... printenv" or one leaked crash dump.
Hardened: the Secret is mounted as a 0440 file, no credential env vars.

Next: make verify-4   (exit 0 = still exploitable)
EOF2

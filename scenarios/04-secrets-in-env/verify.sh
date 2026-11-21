#!/usr/bin/env bash
# Scenario 4 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - the DB password is readable with the "view" role, or is
#                    in the environment of the api or db container
#   1 BLOCKED      - neither, and api still authenticates to the database
#   2 INCONCLUSIVE - the test could not run
#
# It compares against the real value from the Secret instead of looking for
# variable names: a renamed variable or another ConfigMap key still counts.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

VIEWER=(--as=lab-developer --as-group=lab:developers)

kubectl -n "$NS" rollout status deploy/api deploy/db --timeout=60s >/dev/null 2>&1 \
  || verdict "$INCONCLUSIVE" "api or db deployment not ready"
pw=$(kubectl -n "$NS" get secret db-credentials -o jsonpath='{.data.password}' 2>/dev/null | base64 -d)
[ -n "$pw" ] || verdict "$INCONCLUSIVE" "cannot read secret db-credentials as admin"
[ "$(kubectl auth can-i get secrets -n "$NS" "${VIEWER[@]}" 2>/dev/null)" = no ] \
  || verdict "$INCONCLUSIVE" "the 'view' identity can read Secrets - the test is meaningless"

leaks=()
# 1. Everything "view" can list that could carry a value.
if kubectl -n "$NS" get configmaps,pods,deployments,replicasets "${VIEWER[@]}" -o yaml 2>/dev/null \
    | grep -qF -- "$pw"; then
  leaks+=("readable with the 'view' role (ConfigMap / pod spec)")
fi
# 2. The environment a new process in each container inherits.
for app in api db; do
  if kubectl -n "$NS" exec "deploy/$app" -- printenv 2>/dev/null | grep -qF -- "$pw"; then
    leaks+=("in the environment of $app")
  fi
done

if [ ${#leaks[@]} -gt 0 ]; then
  verdict "$EXPLOITABLE" "DB password $(join_list "${leaks[@]}")"
fi

# Control: "no leak" only counts if the app still gets the password somehow.
ready=$(kubectl -n "$NS" exec deploy/api -- wget -q -T 3 -O - http://127.0.0.1:3000/readyz 2>/dev/null)
grep -q '"ready"' <<<"$ready" \
  || verdict "$INCONCLUSIVE" "api cannot reach the database (readyz: ${ready:-no answer})"
verdict "$BLOCKED" "password only in the Secret and its read-only file; api still connects"

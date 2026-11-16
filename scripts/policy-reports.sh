#!/usr/bin/env bash
# Waits for Kyverno's audit evidence in a namespace and prints a summary.
#
# Why waiting is needed: Kyverno does not write PolicyReports synchronously.
# On admission it first records EphemeralReports (one per resource and
# policy evaluation); the reports controller then aggregates them into one
# PolicyReport per resource, typically 10-15 s later in this lab. Reading
# right after "make vulnerable" therefore shows "No resources found".
# Background scans (every 1h by default) refresh the reports afterwards.
#
# Done = at least one PolicyReport exists AND no EphemeralReports are left
# waiting for aggregation.
set -uo pipefail

NS=${NAMESPACE:-demo}
TIMEOUT=${TIMEOUT:-90}
kubectl() { command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" "$@"; }

count() { kubectl -n "$NS" get "$1" -o name 2>/dev/null | wc -l; }

echo "==> Waiting up to ${TIMEOUT}s for Kyverno PolicyReports in '$NS'"
start=$(date +%s)
while :; do
  pr=$(count policyreports); er=$(count ephemeralreports)
  elapsed=$(( $(date +%s) - start ))
  if [ "$pr" -gt 0 ] && [ "$er" -eq 0 ]; then
    echo "    ready after ${elapsed}s: $pr PolicyReports, 0 pending EphemeralReports"
    break
  fi
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "    TIMEOUT: $pr PolicyReports, $er EphemeralReports still pending"
    echo "    Is the namespace labelled lab/kyverno? Are the policies READY (make policies)?"
    exit 1
  fi
  sleep 3
done

echo
kubectl -n "$NS" get policyreports \
  -o custom-columns='KIND:.scope.kind,NAME:.scope.name,PASS:.summary.pass,FAIL:.summary.fail' \
  --sort-by=.scope.name

echo
echo "Failing policies per resource:"
kubectl -n "$NS" get policyreports -o jsonpath='{range .items[*]}{"  "}{.scope.kind}{"/"}{.scope.name}{": "}{range .results[?(@.result=="fail")]}{.policy}{" "}{end}{"\n"}{end}' \
  | sort

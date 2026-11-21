#!/usr/bin/env bash
# Waits for Kyverno's audit evidence in a namespace and prints a summary.
#
# Why waiting is needed: Kyverno does not write PolicyReports synchronously.
# On admission it first records EphemeralReports (one per resource and
# policy evaluation); the reports controller then aggregates them into one
# PolicyReport per resource, typically 10-15 s later in this lab. Reading
# right after "make vulnerable" therefore shows "No resources found".
#
# Second wave: results of Deny (enforce) policies are not written at
# admission at all. The background controller scans every new resource
# shortly after it appears (seconds to about a minute here) and adds them -
# PASS results of enforce policies show up only then, with
# properties.process = "background scan". (A resource that FAILS an enforce
# policy never exists, so there is nothing to report.) The 1h
# --backgroundScanInterval is only the re-scan of unchanged resources.
#
# Done = every Deployment, ReplicaSet and Pod has a PolicyReport, no
# EphemeralReports are pending, and every workload PolicyReport has a
# result for each pod-level policy that selects this namespace (by its
# lab/kyverno label). Policies for other kinds (disallow-secrets-in-
# configmaps) and the reports of those objects are not counted: a
# ConfigMap report has one result, not one per policy.
set -uo pipefail

NS=${NAMESPACE:-demo}
TIMEOUT=${TIMEOUT:-180}
kubectl() { command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" "$@"; }

count() { kubectl -n "$NS" get "$1" -o name 2>/dev/null | wc -l; }

# Pod-level policies whose namespaceSelector lists this namespace's
# lab/kyverno value.
mode=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.lab/kyverno}')
expected=$(kubectl get validatingpolicies \
  -o jsonpath='{range .items[*]}{.spec.matchConstraints.namespaceSelector.matchExpressions[*].values} {.spec.matchConstraints.resourceRules[*].resources}{"\n"}{end}' \
  | grep "\"${mode:-none}\"" | grep -c '"pods"')

# Workload PolicyReports (Deployment, ReplicaSet, Pod): "<kind> <results>".
workload_reports() {
  kubectl -n "$NS" get policyreports \
    -o jsonpath='{range .items[*]}{.scope.kind}{" "}{.summary.pass}{" "}{.summary.fail}{" "}{.summary.warn}{" "}{.summary.error}{" "}{.summary.skip}{"\n"}{end}' 2>/dev/null \
    | awk '$1 ~ /^(Deployment|ReplicaSet|Pod)$/ {print $1, $2+$3+$4+$5+$6}'
}

# Fewest results in any workload PolicyReport (0 if there are none yet).
min_results() {
  workload_reports | awk 'BEGIN{m=-1} {if (m<0 || $2<m) m=$2} END{print (m<0 ? 0 : m)}'
}

echo "==> Waiting up to ${TIMEOUT}s for Kyverno PolicyReports in '$NS' (lab/kyverno=${mode:-none}: $expected policies per resource)"
start=$(date +%s)
while :; do
  pr=$(workload_reports | wc -l); er=$(count ephemeralreports); min=$(min_results)
  workloads=$(kubectl -n "$NS" get deployments,replicasets,pods -o name 2>/dev/null | wc -l)
  elapsed=$(( $(date +%s) - start ))
  if [ "$expected" -gt 0 ] && [ "$pr" -gt 0 ] && [ "$pr" -ge "$workloads" ] \
     && [ "$er" -eq 0 ] && [ "$min" -ge "$expected" ]; then
    echo "    ready after ${elapsed}s: $pr PolicyReports, each with >= $expected results"
    break
  fi
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "    TIMEOUT: $pr PolicyReports for $workloads workloads (fewest results: $min of $expected), $er EphemeralReports pending"
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

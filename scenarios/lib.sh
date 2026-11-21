#!/usr/bin/env bash
# Shared helpers for scenarios/*/run.sh and verify.sh. Source, do not execute.
#
# Threat model used by every scenario: the attacker has achieved code execution
# inside the internet-facing "web" pod (e.g. through an application bug).
# We SIMULATE that foothold with "kubectl exec" into the web container.
# Everything after that runs with the web container's own identity, network
# position and permissions - exactly what a real attacker would get.

LAB_CONTEXT=${KUBE_CONTEXT:-kind-k8s-lab}
NS=${NAMESPACE:-demo}

# Every kubectl call is pinned to the lab cluster, whatever the current context.
kubectl() { command kubectl --context "$LAB_CONTEXT" "$@"; }

# Exit codes for verify.sh. Three outcomes, not two: a broken test must never
# be mistaken for "the defense works".
EXPLOITABLE=0   # the misconfiguration can be abused
BLOCKED=1       # the attack fails because of a defense
# Used only by the scripts that source this file (lib.sh itself never does).
# shellcheck disable=SC2034
INCONCLUSIVE=2  # the test itself could not run (pod missing, tool missing...)

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }

# Waits until the web Deployment is fully rolled out, so "exec deploy/web"
# never lands in an old pod that is still terminating.
require_web() {
  if ! kubectl -n "$NS" rollout status deploy/web --timeout=60s >/dev/null 2>&1; then
    echo "web deployment is not ready in namespace '$NS'" >&2
    return 1
  fi
}

# Run a command inside the web container (the simulated foothold).
in_web() { kubectl -n "$NS" exec deploy/web -c nginx -- "$@"; }

# Name of the overlay currently deployed (from the namespace label).
overlay() {
  kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.lab/overlay}' 2>/dev/null || true
}

# "a" "b c" "d" -> "a, b c, d" (for verdict details built from an array).
join_list() { local out; printf -v out '%s, ' "$@"; echo "${out%, }"; }

# verify.sh helper: print a one-line verdict and exit with the matching code.
verdict() {
  local code=$1; shift
  case $code in
    "$EXPLOITABLE")  echo "EXPLOITABLE: $*" ;;
    "$BLOCKED")      echo "BLOCKED: $*" ;;
    *)               echo "INCONCLUSIVE: $*" ;;
  esac
  exit "$code"
}

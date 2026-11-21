#!/usr/bin/env bash
# Proves that Kyverno blocks bad pods ON ITS OWN, without Pod Security
# Admission.
#
# Why a separate namespace: in the hardened "demo" namespace PSA runs first
# (built-in admission plugins run before validating webhooks), so PSA
# rejects the scenario 1 pod before Kyverno ever sees it. That proves the
# combination, not each layer. Here a throwaway namespace has Kyverno
# enforcement (lab/kyverno=enforce) and NO PSA label, so the cluster default
# (privileged: admit everything) is all PSA would do.
#
# Every request is "kubectl apply --dry-run=server": it goes through the full
# admission chain, but nothing is stored or run.
# Exit 0 if every case matches its expectation, 1 otherwise.
set -uo pipefail
cd "$(dirname "$0")/.."

PROBE_NS=admission-probe
kubectl() { command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" "$@"; }

cleanup() { kubectl delete namespace "$PROBE_NS" --ignore-not-found --wait=false >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> Namespace '$PROBE_NS': Kyverno enforce, no Pod Security label"
cleanup; kubectl wait --for=delete "namespace/$PROBE_NS" --timeout=60s >/dev/null 2>&1
kubectl create namespace "$PROBE_NS" >/dev/null
kubectl label namespace "$PROBE_NS" lab/kyverno=enforce >/dev/null
if kubectl get namespace "$PROBE_NS" -o jsonpath='{.metadata.labels}' | grep -q pod-security; then
  echo "FAIL: namespace unexpectedly carries a pod-security label"; exit 1
fi
echo "    labels: $(kubectl get namespace "$PROBE_NS" -o jsonpath='{.metadata.labels}')"

# A pod that satisfies every policy; each case changes exactly one thing.
# The default image is pinned by digest (require-image-digest); a dry run
# never pulls it.
BUSYBOX=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
#   pod <name> [privileged] [hostpath] [image] [nonroot] [limits] [readonly]
pod() {
  local name=$1 privileged=${2:-false} hostpath=${3:-no} image=${4:-$BUSYBOX}
  local nonroot=${5:-true} limits=${6:-yes} readonly=${7:-true}
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  securityContext:
    runAsNonRoot: $nonroot
    runAsUser: $([ "$nonroot" = true ] && echo 1000 || echo 0)
  containers:
    - name: c
      image: $image
      command: ["sleep", "1"]
      securityContext:
        privileged: $privileged
        readOnlyRootFilesystem: $readonly
$([ "$limits" = yes ] && printf '      resources:\n        limits: {cpu: 50m, memory: 32Mi}\n')
$([ "$hostpath" = yes ] && printf '      volumeMounts:\n        - {name: host, mountPath: /host}\n  volumes:\n    - name: host\n      hostPath: {path: /}\n')
EOF
}

# The compliant pod plus one env entry (flow-style YAML) in its container.
pod_env() { pod "$1" | awk -v e="$2" '{print} /command:/ {print "      env:"; print "        - " e}'; }

failures=0
# check <expect: ADMITTED|DENIED> <description> < manifest
check() {
  local expect=$1 desc=$2 out got by
  out=$(kubectl -n "$PROBE_NS" apply --dry-run=server -o name -f - 2>&1)
  if [ $? -eq 0 ]; then
    got=ADMITTED; by=""
  else
    got=DENIED
    if grep -q 'violates PodSecurity' <<<"$out"; then
      by="by PSA (!)"
    else
      by="by Kyverno: $(grep -oE '[a-z-]+-enforce' <<<"$out" | sort -u | paste -sd, -)"
    fi
  fi
  local mark=PASS
  [ "$got" = "$expect" ] && [[ "$by" != *PSA* ]] || { mark=FAIL; failures=$((failures + 1)); }
  printf '%-5s %-46s %-9s %s\n' "$mark" "$desc" "$got" "$by"
}

echo
printf '%-5s %-46s %-9s %s\n' "" CASE RESULT "WHO DECIDED"
pod good                                      | check ADMITTED "compliant pod (control)"
check DENIED "scenario 1 pod (privileged + hostPath /)" < scenarios/01-privileged-hostpath/probe-pod.yaml
pod privileged true                           | check DENIED   "privileged container only"
pod hostpath false yes                        | check DENIED   "hostPath volume only"
pod latest false no busybox:latest            | check DENIED   "image tag 'latest' (no digest either)"
pod notag false no busybox                    | check DENIED   "no image tag (no digest either)"
pod tagonly false no busybox:1.37            | check DENIED   "version tag without a digest only"
pod root false no "$BUSYBOX" false          | check DENIED   "runs as root only"
pod nolimits false no "$BUSYBOX" true no    | check DENIED   "no resource limits only"
pod rwroot false no "$BUSYBOX" true yes false | check DENIED  "writable root filesystem only"
pod_env envlit '{name: DB_PASSWORD, value: x}' | check DENIED   "password as a literal env var"
pod_env envref '{name: PGPASSWORD, valueFrom: {secretKeyRef: {name: s, key: p}}}' \
                                              | check DENIED   "Secret as env var (secretKeyRef)"
pod_env envfile '{name: PGPASSWORD_FILE, value: /etc/creds/password}' \
                                              | check ADMITTED "*_FILE env var with a path (control)"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm}\ndata: {PGHOST: db, PGPASSWORD: x}\n' \
                                              | check DENIED   "ConfigMap with a PGPASSWORD key"
sed 's/^/      /' <(pod x true | sed -n '/^spec:/,$p' | tail -n +2) | {
  printf 'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: privileged-deploy}\nspec:\n  selector: {matchLabels: {app: x}}\n  template:\n    metadata: {labels: {app: x}}\n    spec:\n'
  cat
} | check DENIED "privileged Deployment (rejected at apply time)"

echo
if [ $failures -eq 0 ]; then
  echo "OK: Kyverno alone enforces every policy; the control pod is admitted."
  exit 0
fi
echo "FAIL: $failures case(s) did not match"
exit 1

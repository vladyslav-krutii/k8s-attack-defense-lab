#!/usr/bin/env bash
# Scenario 6 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - a workload in the namespace runs an image by tag only,
#                    or the namespace still admits a tag-only image
#   1 BLOCKED      - every container image is pinned by digest, and
#                    admission rejects a tag-only pod (while it admits the
#                    same pod pinned by digest)
#   2 INCONCLUSIVE - the test could not run, or the admission probe was
#                    rejected for some other reason
#
# Admission is probed with "kubectl apply --dry-run=server": the full chain
# (PSA + Kyverno) runs, nothing is created.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

kubectl -n "$NS" rollout status deploy/web deploy/api deploy/db --timeout=60s >/dev/null 2>&1 \
  || verdict "$INCONCLUSIVE" "web, api or db deployment not ready"

findings=()
while read -r deploy images; do
  for image in $images; do
    [[ $image == *@sha256:* ]] || findings+=("$deploy runs $image by tag")
  done
done < <(kubectl -n "$NS" get deployments \
  -o jsonpath='{range .items[*]}{.metadata.name} {.spec.template.spec.containers[*].image}{"\n"}{end}')

# A pod that passes Pod Security "restricted" and every other lab policy;
# only the image reference differs between the two probes.
probe() {
  kubectl -n "$NS" apply --dry-run=server -o name -f - 2>&1 <<EOF2
apiVersion: v1
kind: Pod
metadata: {name: lab-s6-probe}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: c
      image: $1
      command: ["sleep", "1"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      resources: {limits: {cpu: 50m, memory: 32Mi}}
EOF2
}
BUSYBOX=busybox:1.37
BUSYBOX_PINNED=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec

if out=$(probe "$BUSYBOX"); then
  findings+=("namespace admits tag-only images")
elif ! grep -q 'require-image-digest' <<<"$out"; then
  verdict "$INCONCLUSIVE" "tag-only probe rejected for another reason: $(head -1 <<<"$out")"
fi

if [ ${#findings[@]} -gt 0 ]; then
  verdict "$EXPLOITABLE" "$(join_list "${findings[@]}")"
fi
out=$(probe "$BUSYBOX_PINNED") \
  || verdict "$INCONCLUSIVE" "control probe (pinned) was rejected too: $(head -1 <<<"$out")"
verdict "$BLOCKED" "all images pinned by digest; admission rejects tag-only images"

#!/usr/bin/env bash
# Scenario 1 check. Exit codes (see lib.sh):
#   0 EXPLOITABLE  - the web container can read the node's filesystem, OR the
#                    namespace would admit a new privileged pod with hostPath
#   1 BLOCKED      - neither
#   2 INCONCLUSIVE - the test could not run
#
# Two checks, because removing the bad patch is not a defense on its own:
#   a) current state: /host/etc/hostname inside web equals the pod's node name.
#      A pod's own /etc/hostname is the POD name, so a match can only come
#      from the node's filesystem.
#   b) guardrail: a privileged + hostPath pod sent with --dry-run=server.
#      It passes through every admission check (Pod Security Admission, and
#      Kyverno from Phase 4) but is never persisted or run. If it would be
#      admitted, anyone with "create pods" (see scenario 2) or a careless
#      deploy brings the escape straight back.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

require_web || verdict "$INCONCLUSIVE" "web deployment not ready"

# a) current state
pod=$(in_web cat /etc/hostname 2>/dev/null) \
  || verdict "$INCONCLUSIVE" "cannot exec into the web container"
node=$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}' 2>/dev/null)
[ -n "$node" ] || verdict "$INCONCLUSIVE" "cannot determine node of pod $pod"

seen=$(in_web cat /host/etc/hostname 2>/dev/null || true)
if [ "$seen" = "$node" ]; then
  verdict "$EXPLOITABLE" "web pod $pod reads the filesystem of node $node via /host"
fi

# b) guardrail
out=$(kubectl -n "$NS" apply --dry-run=server -o name -f - 2>&1 <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: verify-privileged-hostpath
spec:
  containers:
    - name: probe
      image: busybox:1.37
      command: ["sleep", "1"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
EOF
)
rc=$?

if [ $rc -eq 0 ]; then
  verdict "$EXPLOITABLE" "namespace '$NS' would admit a privileged pod with hostPath /"
fi
# Rejected by admission (PSA says "forbidden", webhooks say "denied").
if grep -qiE 'forbidden|denied' <<<"$out"; then
  reason=$(grep -oE 'violates PodSecurity "[^"]*"|denied the request' <<<"$out" | head -1)
  verdict "$BLOCKED" "no node access from web; admission rejects privileged hostPath pods (${reason:-rejected})"
fi
verdict "$INCONCLUSIVE" "dry-run failed for another reason: $(head -1 <<<"$out")"

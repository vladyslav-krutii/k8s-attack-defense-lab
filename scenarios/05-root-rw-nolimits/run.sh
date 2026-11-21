#!/usr/bin/env bash
# Scenario 5 demo: from the (compromised) web container
#  1. who are we, and is the image filesystem writable?
#  2. drop a "tool" into a binary directory and run it (a copy of the
#     image's own busybox - nothing is downloaded; busybox picks its applet
#     from argv[0], so the copy's name must start with "busybox");
#  3. the same from /tmp, the one writable path a read-only pod still has;
#  4. resource ceilings: the cgroup limits, plus a 3-second single-core CPU
#     burn that shows whether the limit actually throttles.
# Everything it creates is removed again. No memory is allocated on purpose:
# exhausting a node would hit every other pod on it.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

echo "Scenario 5: root + writable root FS + no limits  (overlay: $(overlay))"
require_web

step "Identity and root filesystem of the web container"
info "$(in_web id)"
info "root FS mount: $(in_web sh -c "awk '\$2 == \"/\" {split(\$4, o, \",\"); print \$1, o[1]}' /proc/mounts")"

step "Drop a tool into /usr/local/bin and run it"
if err=$(in_web cp /bin/busybox /usr/local/bin/busybox-lab-tool 2>&1); then
  info "copied: $(in_web ls -l /usr/local/bin/busybox-lab-tool)"
  info "runs:   $(in_web /usr/local/bin/busybox-lab-tool echo 'busybox-lab-tool executed from the image filesystem')"
  in_web rm -f /usr/local/bin/busybox-lab-tool
  info "(removed again)"
else
  info "blocked: $(head -1 <<<"$err")"
fi

step "The same from /tmp (writable in both overlays: an emptyDir in hardened)"
# Single quotes on purpose: $? and $rc expand in the container's sh.
# shellcheck disable=SC2016
if in_web sh -c 'cp /bin/busybox /tmp/busybox-lab-tool && /tmp/busybox-lab-tool echo "busybox-lab-tool executed from /tmp"; rc=$?; rm -f /tmp/busybox-lab-tool; exit $rc' \
    2>/dev/null | sed 's/^/    /'; then
  info "read-only root FS does NOT stop this: an emptyDir cannot be mounted"
  info "noexec. Only an image without a shell/busybox (distroless) and"
  info "runtime detection (Falco) cover it."
else
  info "blocked"
fi

step "Resource ceilings (cgroup v2) of the web container"
info "memory.max = $(in_web cat /sys/fs/cgroup/memory.max)   ('max' = no limit)"
info "cpu.max    = $(in_web cat /sys/fs/cgroup/cpu.max)   (quota period; 'max' = no limit)"
info "node allocatable: $(kubectl get node "$(kubectl -n "$NS" get pod -l app=web -o jsonpath='{.items[0].spec.nodeName}')" \
  -o jsonpath='{.status.allocatable.cpu} CPUs, {.status.allocatable.memory}')"

step "3-second CPU burn on one core: does the limit throttle it?"
# Single quotes on purpose: the whole script runs in the container's sh.
# shellcheck disable=SC2016
burn=$(in_web sh -c '
  t0=$(awk "/^nr_throttled/ {print \$2}" /sys/fs/cgroup/cpu.stat)
  timeout 3 sh -c "while :; do :; done" 2>/dev/null || true
  t1=$(awk "/^nr_throttled/ {print \$2}" /sys/fs/cgroup/cpu.stat)
  echo $((t1 - t0))')
info "throttled periods during the burn: $burn"
if [ "$burn" -eq 0 ]; then
  info "-> no ceiling: N busy loops would take N cores of the node"
else
  info "-> the CPU limit stops the container at its quota"
fi

cat <<'EOF2'

Impact (vulnerable): as root with a writable image filesystem, an attacker
can add tools, change binaries and config, and hide in the container; with
no limits one container can take every CPU and all memory on the node
(denial of service for every other pod there).
Hardened: non-root, read-only root FS (writes fail with EROFS), CPU and
memory limits. The /tmp emptyDir stays writable - a deliberate trade-off.

Next: make verify-5   (exit 0 = still exploitable)
EOF2

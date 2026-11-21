#!/usr/bin/env bash
# Scenario 5 check, from INSIDE each app container (web, api, db). Exit codes:
#   0 EXPLOITABLE  - any container runs as root, has a writable root
#                    filesystem, or has no CPU or memory limit
#   1 BLOCKED      - none of that, in all three
#   2 INCONCLUSIVE - the test could not run (pod missing, no cgroup v2...)
#
# It reads what the kernel enforces (mount flags, cgroup files), not the pod
# spec: a limit or flag that never reached the container does not count.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

require_web || verdict "$INCONCLUSIVE" "web deployment not ready"
kubectl -n "$NS" rollout status deploy/api deploy/db --timeout=60s >/dev/null 2>&1 \
  || verdict "$INCONCLUSIVE" "api or db deployment not ready"

findings=()
for app in web api db; do
  # One exec per container: uid, root FS mode, memory.max, cpu quota.
  read -r uid rootfs mem cpu < <(kubectl -n "$NS" exec "deploy/$app" -- sh -c '
    printf "%s %s %s %s\n" "$(id -u)" \
      "$(awk "\$2 == \"/\" {split(\$4, o, \",\"); print o[1]}" /proc/mounts)" \
      "$(cat /sys/fs/cgroup/memory.max)" "$(cut -d" " -f1 /sys/fs/cgroup/cpu.max)"' 2>/dev/null)
  [ -n "${cpu:-}" ] || verdict "$INCONCLUSIVE" "cannot read uid/mounts/cgroup v2 files in $app"
  [ "$uid" = 0 ] && findings+=("$app runs as root")
  [ "$rootfs" = rw ] && findings+=("$app root FS writable")
  [ "$mem" = max ] && findings+=("$app no memory limit")
  [ "$cpu" = max ] && findings+=("$app no CPU limit")
done

if [ ${#findings[@]} -gt 0 ]; then
  verdict "$EXPLOITABLE" "$(IFS=';'; echo "${findings[*]}" | sed 's/;/, /g')"
fi
verdict "$BLOCKED" "web, api, db: non-root, read-only root FS, CPU and memory limits"

#!/usr/bin/env bash
# Runtime detection check for the three custom Falco rules
# (detection/falco/lab-rules.yaml).
#
# 1. Quiet windows - no lab alert may appear while the app starts up
#    (Postgres initdb, nginx entrypoint, probes) or while it serves normal
#    traffic (scripts/smoke.sh: web -> api -> db). This is the false-positive
#    check.
# 2. Attack window - run the scenario demos plus an RCE-style
#    "sh -c id" without a TTY, then count alerts per rule and compare them
#    with what the deployed overlay should produce:
#
#      rule                       vulnerable   hardened
#      1 shell without terminal   fires        fires (*)
#      2 credentials read         fires        silent: no token, no hostPath
#      3 unexpected outbound      fires        silent: NetworkPolicy drops it,
#                                              connect() never succeeds
#
#    (*) Pod hardening does not take away an admin's pods/exec right or the
#    shell in the nginx image, so the exec'd shell still runs - and should
#    be reported. Making rule 1 silent would need an image without a shell.
#
# Run it right after "make vulnerable" or "make hardened": the start-up
# window is measured from the creation of the namespace.
# Exit 0 if everything matches, 1 on a mismatch, 2 if the check could not run.
set -uo pipefail
cd "$(dirname "$0")/.."
source scenarios/lib.sh

R1="Shell spawned without a terminal in a pod"
R2="Kubernetes credentials read in a pod"
R3="Unexpected outbound connection from web"
SETTLE=15   # seconds after the last pod became Ready that still count as start-up

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
inconclusive() { echo "INCONCLUSIVE: $*"; exit 2; }

ov=$(overlay)
case $ov in
  vulnerable) expect=(fire fire fire) ;;
  hardened)   expect=(fire silent silent) ;;
  *) inconclusive "namespace '$NS' has overlay '${ov:-none}', expected vulnerable or hardened" ;;
esac
echo "==> Overlay: $ov"

kubectl -n falco rollout status ds/falco --timeout=60s >/dev/null 2>&1 \
  || inconclusive "Falco is not running (make falco)"
kubectl -n falco get configmap falco-rules -o jsonpath='{.data}' 2>/dev/null \
  | grep -q 'Lab Shell Spawned Without Terminal' \
  || inconclusive "lab rules are not loaded into Falco (make falco)"
require_web || inconclusive "web is not ready"

# Start-up window: namespace creation .. last pod Ready + SETTLE seconds.
ns_created=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.creationTimestamp}')
last_ready=$(kubectl -n "$NS" get pods \
  -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].lastTransitionTime}{"\n"}{end}' \
  | sort | tail -1)
startup_end=$(date -u -d "$last_ready + $SETTLE seconds" +%Y-%m-%dT%H:%M:%SZ)
falco_started=$(kubectl -n falco get pods -l app.kubernetes.io/name=falco \
  -o jsonpath='{range .items[*]}{.status.startTime}{"\n"}{end}' | sort | tail -1)
startup_seen=yes
[[ "$falco_started" > "$ns_created" ]] && startup_seen=no
# The windows must not overlap: if we run right after the deploy, wait until
# the start-up window has closed before generating any traffic ourselves.
wait_s=$(( $(date -u -d "$startup_end" +%s) - $(date -u +%s) + 1 ))
if (( wait_s > 0 )); then
  echo "==> Waiting ${wait_s}s for the start-up window to close"
  sleep "$wait_s"
fi

echo "==> Normal traffic (smoke test)"
legit_start=$(now)
bash scripts/smoke.sh >/dev/null 2>&1 || inconclusive "smoke test failed - the app itself is broken"
legit_end=$(now)

echo "==> Attack triggers (scenario demos + RCE-style shell)"
sleep 1
attack_start=$(now)
in_web sh -c id >/dev/null 2>&1 || true
for s in scenarios/0[1-3]-*/run.sh; do
  bash "$s" >/dev/null 2>&1 || true
  echo "    ran $s"
done
sleep 5   # let Falco flush the last events
attack_end=$(now)

# One read of the logs; kubectl --timestamps prefixes every line with an
# RFC 3339 time, which compares correctly as a string.
logs=$(kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco \
  --since-time="$ns_created" --timestamps --tail=-1 --max-log-requests 5 2>/dev/null \
  | grep -F "ns=$NS ")

# window <from> <to>: alert lines whose timestamp falls in [from, to].
window() { awk -v a="$1" -v b="$2" 'substr($1,1,19) >= substr(a,1,19) && substr($1,1,19) <= substr(b,1,19)' <<<"$logs"; }
lab_alerts() { grep -F -e "$R1" -e "$R2" -e "$R3" || true; }

fail=0
echo
echo "==> False-positive check"
if [[ $startup_seen == yes ]]; then
  fp=$(window "$ns_created" "$startup_end" | lab_alerts)
  if [[ -z $fp ]]; then echo "PASS  start-up ($ns_created .. $startup_end): no lab alerts"
  else echo "FAIL  start-up: lab alerts while the app started:"; cut -c1-220 <<<"$fp"; fail=1; fi
else
  echo "SKIP  start-up: Falco restarted after the deploy, the window was not observed"
fi
fp=$(window "$legit_start" "$legit_end" | lab_alerts)
if [[ -z $fp ]]; then echo "PASS  normal traffic: no lab alerts"
else echo "FAIL  normal traffic raised lab alerts:"; cut -c1-220 <<<"$fp"; fail=1; fi

echo
echo "==> Detection check"
attack=$(window "$attack_start" "$attack_end")
printf '%-6s %-44s %-8s %-6s %s\n' RESULT RULE EXPECTED ALERTS
i=0
for r in "$R1" "$R2" "$R3"; do
  n=$(grep -cF "$r" <<<"$attack" || true)
  want=${expect[$i]}
  if { [[ $want == fire ]] && (( n > 0 )); } || { [[ $want == silent ]] && (( n == 0 )); }; then
    res=PASS
  else
    res=FAIL; fail=1
  fi
  printf '%-6s %-44s %-8s %s\n' "$res" "$r" "$want" "$n"
  i=$((i + 1))
done

echo
echo "==> Sample alerts (first per rule; output fields after ')' trimmed)"
for r in "$R1" "$R2" "$R3"; do
  grep -F "$r" <<<"$attack" | head -1 | sed -E 's/^[^ ]+ //; s/\) container_id=.*/)/' | cut -c1-300
done

exit $fail

#!/usr/bin/env bash
# Runs every scenarios/*/verify.sh and prints one table row per scenario.
#
#   verify-all.sh                     report only, always exits 0
#   verify-all.sh --expect blocked    exit 1 unless EVERY scenario is BLOCKED
#   verify-all.sh --expect exploitable  exit 1 unless every one is EXPLOITABLE
#
# --expect is what CI (Phase 6) uses: vulnerable must stay exploitable (the
# demo still works) and hardened must block everything (the fix still works).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

expect=""
if [ "${1:-}" = "--expect" ]; then
  case ${2:-} in
    blocked) expect=1 ;;
    exploitable) expect=0 ;;
    *) echo "usage: $0 [--expect blocked|exploitable]" >&2; exit 2 ;;
  esac
fi

names=([0]=EXPLOITABLE [1]=BLOCKED [2]=INCONCLUSIVE)
overlay=$(command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" \
  get namespace "${NAMESPACE:-demo}" -o jsonpath='{.metadata.labels.lab/overlay}' 2>/dev/null)

printf 'overlay: %s\n\n' "${overlay:-unknown}"
printf '%-28s %-13s %s\n' SCENARIO RESULT DETAIL
failed=0
for script in scenarios/0*/verify.sh; do
  scenario=$(basename "$(dirname "$script")")
  out=$(bash "$script" 2>&1)
  rc=$?
  detail=$(tail -1 <<<"$out")
  printf '%-28s %-13s %s\n' "$scenario" "${names[$rc]:-ERROR($rc)}" "${detail#*: }"
  if [ -n "$expect" ] && [ "$rc" != "$expect" ]; then failed=1; fi
done

if [ -n "$expect" ]; then
  echo
  if [ $failed -eq 0 ]; then echo "OK: all scenarios ${names[$expect]}"; else echo "FAIL: expected all ${names[$expect]}"; fi
fi
exit $failed

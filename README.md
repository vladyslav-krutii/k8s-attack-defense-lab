# k8s-attack-defense-lab

A local Kubernetes lab that shows Kubernetes misconfigurations being
exploited and then blocked. The same three-tier app (nginx `web` → Node
`api` → Postgres `db`) is deployed twice from one base:

- **vulnerable**: realistic misconfigurations, each one exploited by a
  minimal, safe demo;
- **hardened**: the same app with defense layers. Every attack is blocked
  and the app still works end to end.

Every scenario has a `verify.sh` that tests the real attack path and exits
`0` (exploitable), `1` (blocked) or `2` (inconclusive), so "it's fixed" is a
test result rather than a claim. Kyverno enforces the fixes at admission,
and Falco detects the attacks at runtime.

> Runs only on a local [kind](https://kind.sigs.k8s.io/) cluster. No real
> targets and no public exposure. The demos show impact (a masked
> password, a Secret name) and do nothing destructive.

## Scenarios

| # | Scenario | vulnerable | hardened | Blocked by |
|---|---|---|---|---|
| 1 | [Privileged pod + hostPath `/`](scenarios/01-privileged-hostpath/) | node root FS, kubelet PKI | BLOCKED | Pod Security `restricted`, Kyverno |
| 2 | [Over-permissive RBAC + auto-mounted token](scenarios/02-rbac-sa-token/) | reads every Secret | BLOCKED | no token, no RoleBinding, egress policy |
| 3 | [No NetworkPolicy](scenarios/03-no-networkpolicy/) | web → db:5432 directly | BLOCKED | default-deny + explicit allows (Calico) |
| 4 | [Credentials in env vars / ConfigMap](scenarios/04-secrets-in-env/) | password via `view` role and `printenv` | BLOCKED | Secret as a 0440 read-only file, Kyverno |
| 5 | Root + no limits + writable root FS | *in progress (Phase 5)* | | |
| 6 | Supply chain: mutable tags | *in progress (Phase 5)* | | |
| 7 | SSRF → Kubernetes API (SecScan) | *planned* | | |

## Defense layers (hardened overlay)

1. **Pod Security**: the `restricted` PSA level; non-root, no privilege
   escalation, all capabilities dropped, `RuntimeDefault` seccomp.
2. **Identity & RBAC**: one ServiceAccount per workload, no API token, no
   RoleBindings.
3. **Network**: default-deny ingress and egress; only web → api → db and
   DNS are allowed.
4. **Secrets as files**: no credentials in env vars or ConfigMaps.
5. **Admission control**: Kyverno `ValidatingPolicy` (CEL), audit in
   vulnerable and enforce in hardened. [`policies/kyverno/`](policies/kyverno/)
6. **Runtime detection**: Falco (modern eBPF, not privileged) with custom
   rules. [`detection/falco/`](detection/falco/)

## Quickstart

Requires Docker, kind, `make` and bash (Linux or WSL2). `make helm kubectl
kyverno-cli` installs pinned, checksum-verified tools into `~/.local/bin`.

```bash
make cluster kyverno policies falco     # kind + Calico, Kyverno, Falco

make vulnerable && make smoke           # deploy the misconfigured app
make scenario-2                         # run one attack demo
bash scripts/verify-all.sh --expect exploitable

make hardened && make smoke             # same app, defenses on
bash scripts/verify-all.sh --expect blocked
make verify-detection                   # Falco rules fire / stay silent as expected

make policy-test verify-admission reports
make help                               # all targets
```

## Docs

- [`docs/NEXT.md`](docs/NEXT.md): current state, the full re-check
  commands and the roadmap.
- [`docs/LEARNING.md`](docs/LEARNING.md): a log of every change and the
  reason for it, with interview questions.
- [`docs/design-decisions.md`](docs/design-decisions.md): trade-offs.

The full README (architecture diagram, threat model, results) comes in
Phase 7.

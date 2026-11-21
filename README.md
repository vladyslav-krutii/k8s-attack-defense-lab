# k8s-attack-defense-lab

[![ci](https://github.com/vladyslav-krutii/k8s-attack-defense-lab/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vladyslav-krutii/k8s-attack-defense-lab/actions/workflows/ci.yml)

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
| 5 | [Root + writable root FS + no limits](scenarios/05-root-rw-nolimits/) | tool dropped into `/usr/local/bin`, no CPU/memory ceiling | BLOCKED | read-only root FS, requests/limits, Kyverno |
| 6 | [Supply chain: mutable image tags](scenarios/06-mutable-image-tag/) | re-tagged `api:latest` runs after a restart | BLOCKED | every image pinned by digest, Kyverno |
| 7 | SSRF → Kubernetes API (SecScan) | *planned* | | |

## Defense layers (hardened overlay)

1. **Pod Security**: the `restricted` PSA level; non-root, no privilege
   escalation, all capabilities dropped, `RuntimeDefault` seccomp.
2. **Identity & RBAC**: one ServiceAccount per workload, no API token, no
   RoleBindings.
3. **Network**: default-deny ingress and egress; only web → api → db and
   DNS are allowed.
4. **Secrets as files**: no credentials in env vars or ConfigMaps.
5. **Runtime limits**: read-only root FS (explicit emptyDirs with a
   `sizeLimit`), CPU and memory requests and limits.
6. **Supply chain**: images referenced as `name:tag@sha256:digest`.
7. **Admission control**: 9 Kyverno `ValidatingPolicy` (CEL), audit in
   vulnerable and enforce in hardened. [`policies/kyverno/`](policies/kyverno/)
8. **Runtime detection**: Falco (modern eBPF, not privileged) with six
   custom rules, including the residual risks the layers above leave open.
   [`detection/falco/`](detection/falco/)

Each scenario README also records what its fix does *not* cover.

## Quickstart

Requires Docker, kind, `make` and bash (Linux or WSL2). `make helm kubectl
kyverno-cli` installs pinned, checksum-verified tools into `~/.local/bin`.

```bash
make cluster kyverno policies falco     # kind + Calico, Kyverno, Falco

make vulnerable                         # deploy the misconfigured app
make verify-detection                   # Falco rules (run first, right after a deploy)
make smoke                              # the app works
bash scripts/verify-all.sh --expect exploitable
make scenario-2                         # run one attack demo

make hardened                           # same app, defenses on
make verify-detection && make smoke
bash scripts/verify-all.sh --expect blocked

make policy-test verify-admission reports
make help                               # all targets
```

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the same make
targets on every push:

- **static** (~20 s): kustomize + kubeconform, `kyverno test`, shellcheck,
  Falco rule compilation, gitleaks, `trivy config`. Hardened must be clean;
  vulnerable must still have HIGH findings.
- **image** (~40 s): the api image is pushed to a throwaway local registry
  and scanned with trivy **by digest**; the SBOM is kept as an artifact.
- **e2e** (~5 min): kind + Calico + Kyverno + Falco. Both overlays are
  deployed, with `verify-all --expect exploitable / blocked`,
  `verify-detection`, smoke, `verify-admission` and `reports`.

Actions are pinned by SHA, tools by version and SHA-256, and the token is
read-only. Locally, `make ci-static scan-image` runs the first two jobs.

## Docs

- [`docs/NEXT.md`](docs/NEXT.md): current state, the full re-check
  commands and the roadmap.
- [`docs/LEARNING.md`](docs/LEARNING.md): a log of every change and the
  reason for it, with interview questions.
- [`docs/design-decisions.md`](docs/design-decisions.md): trade-offs.

The full README (architecture diagram, threat model, results) comes in
Phase 7.

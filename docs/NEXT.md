# Next session handoff

_Last updated: 2026-11-16, at commit `18eece1` (pushed to origin/main)._

## Current state

- **Phases 0–3 done.** kind cluster `kind-k8s-lab` (K8s 1.36.4, Calico
  v3.33.0), demo app web → api → db, `make vulnerable` / `make hardened`
  (each deploys into a fresh `demo` namespace), scenarios 1–3 with `run.sh`
  and `verify.sh`, and `scripts/verify-all.sh --expect blocked|exploitable`.
- **Phase 4, steps 1–3 done.**
  1. Pinned, checksum-verified tools in `~/.local/bin`: `make helm` (v4.3.2),
     `make kubectl` (v1.36.4), `make kyverno-cli` (v1.20.0).
  2. Kyverno 1.20 (`make kyverno`, chart 3.10.0). Five `ValidatingPolicy`
     resources (`policies.kyverno.io/v1`, CEL; legacy `ClusterPolicy` is no
     longer executed in 1.20) with `make policy-test` (85/85). The namespace
     label `lab/kyverno=audit|enforce` picks the mode: vulnerable audits,
     hardened enforces. `require-resource-limits` only audits until Phase 5.
     `make verify-admission` proves Kyverno alone blocks the scenario 1 pod in
     a namespace without PSA. `make reports` waits for the asynchronous
     PolicyReports (about 10–15 s).
  3. Falco 0.45.2 (`make falco`, chart 9.2.2) runs `modern_ebpf`
     least-privileged (CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE, CAP_SYS_PTRACE,
     not privileged) on both nodes. The stock rule "A shell was spawned in a
     container with an attached terminal" fires for `kubectl exec -it` into
     web. `make falco-logs` follows alerts.
- Trade-offs are recorded in [`design-decisions.md`](design-decisions.md).

## Next: Phase 4, step 4 — custom Falco rules

Put them in `detection/falco/` and load them through the chart's `customRules`.
Show each rule firing while the matching scenario runs on the **vulnerable**
overlay, ideally with a script that runs the scenario and greps the
alert.

1. **Shell in a container without a TTY.** The stock rule needs a terminal,
   but an attacker with web RCE has none (`kubectl exec -- sh -c ...` does not
   trigger it). Trigger: any scenario's `run.sh`.
2. **Read of the service account token or kubelet PKI.** Opens of
   `/var/run/secrets/kubernetes.io/serviceaccount/token`,
   `/host/var/lib/kubelet/pki/*` and other pods' token paths under
   `/var/lib/kubelet/pods`. Triggers: scenarios 2 and 1.
3. **Unexpected outbound connection from web.** Anything other than
   `api:3000` or DNS (53). Triggers: scenario 3 (`db:5432`) and scenario 2
   (API server 443).

Watch out for:

- `user`/`parent` show `<NA>` for exec'd processes (BPF iterators are
  disabled because the pod is not in the host PID namespace), so do not key
  rules on those fields.
- Kubernetes metadata (`k8s.ns.name`, `k8s.pod.name`) comes from container
  labels; no k8s-metacollector is installed.

## Open question (check the Kyverno docs)

In hardened, `make reports` shows `PASS 0` per resource: only the audit-mode
`require-resource-limits-audit` FAIL appears. Why don't Enforce (`Deny`)
policies record PASS results in admission reports? Is this by design, and
do they appear only after the background scan (`--backgroundScanInterval=1h`)?
Check the Kyverno 1.20 reporting docs before relying on reports as evidence
for enforce-mode policies.

## Later phases

- Phase 5: scenarios 4–6. The hardened overlay gets `readOnlyRootFilesystem`
  and resource limits, and `require-resource-limits` moves to enforce.
- Phase 6: CI (kubeconform, kube-linter or kubescape, trivy config,
  `kyverno test`, e2e in kind with `verify-all --expect`).
- Phase 7: README with the diagram, results table and interview talking
  points.

## Environment gotchas

- Docker Desktop must be running; the kind nodes live in it. If `kubectl`
  can't reach the cluster, start Desktop first.
- Kali's login shell is **bash** (put aliases in `~/.bashrc`, not `~/.zshrc`).
- From PowerShell 5.1, run Kali commands via a script file
  (`wsl -d kali-linux -e bash -lc 'bash file.sh'`); inline quotes and `$?`
  get mangled.
- `make` hides exit codes 1 vs 2. Call `verify.sh` directly when the code
  matters.

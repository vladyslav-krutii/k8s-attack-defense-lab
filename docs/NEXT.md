# Next session handoff

_Last updated: 2026-11-20. Phase 4 is done._

## Current state

- **Phases 0–3 done.** kind cluster `kind-k8s-lab` (K8s 1.36.4, Calico
  v3.33.0), demo app web → api → db, `make vulnerable` / `make hardened`
  (each deploys into a fresh `demo` namespace), scenarios 1–3 with `run.sh`
  and `verify.sh`, `scripts/verify-all.sh --expect blocked|exploitable`.
- **Phase 4 done (admission control + runtime detection).**
  1. Pinned, checksum-verified tools: `make helm kubectl kyverno-cli`.
  2. Kyverno 1.20: five `ValidatingPolicy` (CEL), audit/enforce by the
     namespace label `lab/kyverno`, `make policy-test` (85/85),
     `make verify-admission` (Kyverno alone blocks scenario 1 without PSA),
     `make reports` (waits for admission *and* background-scan results).
  3. Falco 0.45.2, `modern_ebpf`, four capabilities instead of privileged.
     The AppArmor profile is set through `securityContext`, not the
     deprecated annotation, and `make falco` fails if Falco ends up
     privileged. `rule_matching: all`.
  4. Three custom rules in [`detection/falco/`](../detection/falco/README.md):
     shell without a TTY, read of Kubernetes credentials, unexpected outbound
     connection from web. `make verify-detection` runs scenarios 1–3 and
     checks the expected matrix plus two false-positive windows:

     | rule | vulnerable | hardened |
     |---|---|---|
     | shell without terminal | fires | fires (exec is still allowed; the shell exists) |
     | credentials read | fires | silent |
     | unexpected outbound | fires | silent |

- **Reproducibility check (2026-11-20).** The cluster was rebuilt from
  scratch with `make cluster kyverno policies falco hardened smoke`, all
  green.
- Open question from last time, answered: enforce-policy PASS results come
  from the background scan of new resources, not from admission (details in
  [`LEARNING.md`](LEARNING.md)).
- Notes: trade-offs in [`design-decisions.md`](design-decisions.md); a
  per-commit learning log with interview questions in
  [`LEARNING.md`](LEARNING.md). Add an entry there for every new commit.

## Full re-check after a cluster rebuild

```bash
make cluster kyverno policies falco
make vulnerable && make smoke && bash scripts/verify-all.sh --expect exploitable && make verify-detection
make hardened   && make smoke && bash scripts/verify-all.sh --expect blocked     && make verify-detection
make policy-test verify-admission reports
```

## Next: Phase 5 — scenarios 4–6

Same pattern as 1–3: misconfiguration in `vulnerable`, `run.sh` (minimal,
safe impact), `verify.sh` (0/1/2), fix in `hardened`, Kyverno policy
(+ `kyverno test` fixtures), Falco rule where it adds signal, a row in
`verify-all` / `verify-detection`. One scenario per commit, plus LEARNING
entries.

### Scenario 4 — secrets in environment variables

- **Misconfiguration.** The api gets `DB_PASSWORD` as a literal `env.value`
  in the Deployment (or a `secretKeyRef` env var).
- **Impact (safe).** Anyone with `get deployments` (e.g. the `view` role,
  which deliberately excludes Secrets) reads the password from the pod spec.
  Inside the container it shows up in `/proc/1/environ`, and it leaks into
  crash dumps and `kubectl describe`. Show the masked value only.
- **Fix.** A Secret mounted as a read-only file (`defaultMode: 0400`). The
  app reads `DB_PASSWORD_FILE`, which needs a small `server.ts` change.
- **Kyverno.** Deny `env[].value` for names matching
  `*PASSWORD*|*SECRET*|*TOKEN*|*KEY*`. Decide whether `secretKeyRef` env
  vars are audit-only (a trade-off: common practice, smaller risk).
- **Falco (optional).** A read of `/proc/*/environ` from a shell.

### Scenario 5 — root, no limits, writable root filesystem

- **Misconfiguration.** web runs as root with a writable root FS and no
  resource limits (the vulnerable overlay already sets root).
- **Impact (safe).** Write a marker into `/usr/share/nginx/html` and show
  it served by web (defacement / persistence). Show `memory.max = max` in
  the container's cgroup. No real exhaustion.
- **Fix (hardened).** `readOnlyRootFilesystem: true` with `emptyDir` for
  nginx's writable paths (`/tmp`, `/var/cache/nginx`, pid), plus requests
  and limits on all three workloads.
- **Kyverno.** New `require-readonly-rootfs`; `require-resource-limits`
  moves from audit to enforce (remove the `$patch: delete` in
  `policies/kyverno/enforce`).
- **Falco.** A write below the web root or binary directories in an app pod.

### Scenario 6 — supply chain: mutable tags

- **Misconfiguration.** An image by tag `:latest` (or any tag) with
  `imagePullPolicy: Always`/`IfNotPresent`, no digest.
- **Impact (safe, local only).** Re-tag a different local build as the same
  tag, `kind load` it, restart the pod: the same manifest now runs other
  code. Show the image ID change; no registry, nothing published.
- **Fix.** Pin by digest (`image@sha256:...`) in hardened. Trivy image scan
  in CI (Phase 6).
- **Kyverno.** `disallow-latest-tag` already exists. Add `require-image-digest`
  (audit first, then enforce in hardened).

## Later

- **Scenario 7 — SecScan (planned).** SecScan will be deployed into this
  cluster as scenario 7: **SSRF → Kubernetes API**. A URL fetched by SecScan
  is pointed at `https://kubernetes.default.svc` (with a mounted token) or at
  other internal Services. Defenses: no token automount, egress
  NetworkPolicy without the API server, the Falco outbound rule
  generalized to SecScan, and a Kyverno **`ImageValidatingPolicy`** that
  admits only SecScan images with a valid **Cosign signature** (decide key
  vs keyless; the signing happens in SecScan's CI).
- **Phase 6: CI.** kubeconform, kube-linter or kubescape, trivy config,
  `kyverno test`, an e2e job in kind with `verify-all --expect`. Check
  whether Falco's `modern_ebpf` works on GitHub-hosted runners before adding
  `verify-detection` to CI.
- **Phase 7: README.** A diagram, the results table (verify + detection
  matrices) and interview talking points (use `LEARNING.md`).

## Environment gotchas

- Docker Desktop must be running; the kind nodes live in it.
- Kali's login shell is **bash** (put aliases in `~/.bashrc`).
- From PowerShell 5.1, run Kali commands from a script file
  (`wsl -d kali-linux -e bash -lc 'bash file.sh'`); inline quotes and `$?`
  get mangled.
- `make` hides exit codes 1 vs 2. Call scripts directly when the code
  matters.
- `kubectl logs -l ...` defaults to `--tail=10` per pod. Pass `--tail=-1`
  when searching Falco logs.

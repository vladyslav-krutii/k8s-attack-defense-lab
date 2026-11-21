# Next session handoff

_Last updated: 2026-11-21. Phase 5 is done._

## Current state

- **Phases 0–3 done.** kind cluster `kind-k8s-lab` (K8s 1.36.4, Calico
  v3.33.0), demo app web → api → db, `make vulnerable` / `make hardened`
  (each deploys into a fresh `demo` namespace), scenarios with `run.sh` and
  `verify.sh`, and `scripts/verify-all.sh --expect blocked|exploitable`.
- **Phase 4 done (admission control + runtime detection).** Kyverno 1.20
  `ValidatingPolicy` (CEL), audit or enforce chosen by the namespace label
  `lab/kyverno`. Falco 0.45.2 runs with `modern_ebpf`, not privileged, and
  has custom rules in [`detection/falco/`](../detection/falco/README.md).
- **Phase 5 done (scenarios 4–6).** Hardened layers 4–6, Kyverno
  policies (four new, `require-resource-limits` moved to enforce), three
  new Falco rules, plus the api image `0.2.0`, which reads
  `PGPASSWORD_FILE`.

  | # | Scenario | vulnerable | hardened (layer) | Kyverno (enforce in hardened) |
  |---|---|---|---|---|
  | 4 | credentials in env / ConfigMap | `view` reads the password; `printenv` in api/db | Secret as a 0440 read-only file (4) | `disallow-secrets-in-env`, `disallow-secrets-in-configmaps` |
  | 5 | root + writable root FS + no limits | tool dropped into `/usr/local/bin`; `memory.max = max` | `readOnlyRootFilesystem`, emptyDir with `sizeLimit`, requests and limits (5) | `require-readonly-rootfs`; `require-resource-limits` now enforce |
  | 6 | mutable image tags | re-tagged `api:latest` runs after a restart | `name:tag@sha256:…` for every image (6) | `require-image-digest` |

- **Checks (2026-11-21, both overlays):**
  - `verify-all`: 6/6 EXPLOITABLE on vulnerable, 6/6 BLOCKED on hardened;
  - smoke: PASS;
  - `make policy-test`: 105/105;
  - `make verify-admission`: 15/15;
  - `make reports`: hardened 8 PASS / 0 FAIL per workload;
  - `make verify-detection` (six rules):

    | rule | vulnerable | hardened |
    |---|---|---|
    | shell without terminal | fires | fires (exec is allowed; the shell exists) |
    | credentials read | fires | silent |
    | unexpected outbound | fires | silent |
    | process environment read | fires | fires (the read itself is the signal) |
    | write below binary dir | fires | silent (EROFS) |
    | exec from writable dir | fires | fires (`/tmp` emptyDir: the residual risk) |

- **Honest limits, documented in the scenario READMEs.**
  - Scenario 4: code running as the app user can still read the file.
  - Scenario 5: a binary dropped into the `/tmp` emptyDir still runs (no
    `noexec` for emptyDir). Falco rule 6 covers it.
  - Scenario 6: a digest does not say *who* built the image. Signatures
    come with scenario 7.
- **New in the workflow.**
  - `make hardened` renders the overlay through `scripts/render-pinned.sh`
    (the api digest comes from containerd on the kind nodes), so
    `kubectl apply -k k8s/overlays/hardened` alone is rejected by
    `require-image-digest`. That is intended.
  - `make build` uses `--provenance=false`, so cached rebuilds keep their
    digest.
- **Fixed on the way.**
  - The Kyverno reports controller kept losing its leader lease at the
    chart's 128Mi memory limit (exit 0, no OOM kill); it now has 512Mi.
  - `make reports` now counts only workload reports.
- **Root README.** Short version with the scenario table and a quickstart;
  the full one is Phase 7.
- **SecScan.** The `secscan` namespace (another project, with its own
  NetworkPolicy and `NamespacedImageValidatingPolicy`) was not touched. Lab
  policies only select namespaces with a `lab/kyverno` label, and the Falco
  lab rules only cover `demo`.
- Notes: trade-offs in [`design-decisions.md`](design-decisions.md), a log
  with interview questions in [`LEARNING.md`](LEARNING.md). Add an entry
  there for every new commit.

## Full re-check after a cluster rebuild

```bash
make cluster kyverno policies falco
make vulnerable && make smoke && bash scripts/verify-all.sh --expect exploitable && make verify-detection
make hardened   && make smoke && bash scripts/verify-all.sh --expect blocked     && make verify-detection
make policy-test verify-admission reports
```

`make verify-detection` has to run right after a deploy (it measures the
start-up window from the namespace creation). Scenario 6's `run.sh` needs
`docker` and `kind` on the host.

## Next: Phase 6 — CI for the lab (GitHub Actions)

There is no CI yet (`.github/` does not exist). Plan, from cheap to
expensive:

1. **Static job (every push and PR, about a minute).**
   - `kubectl kustomize` for base, both overlays and `policies/kyverno`. The
     hardened overlay renders without the api digest, which is fine for
     linting.
   - `kubeconform -strict -summary` against the K8s 1.36 schemas, plus the
     Kyverno CRD schemas (datree CRDs-catalog) for the policies.
   - `kyverno test policies/kyverno/tests --require-tests` with the pinned
     CLI (`scripts/install-kyverno-cli.sh`).
   - `shellcheck` on `scripts/*.sh` and `scenarios/**/*.sh`. Expect some
     findings to fix first, e.g. `SC2016` in the intentional single-quoted
     `sh -c` scripts.
   - Falco rules validation: `falco -V lab-rules.yaml` in the pinned Falco
     image, or `falcoctl`.
   - Secret scanning (gitleaks) and `trivy config` on the manifests. The
     vulnerable overlay *must* produce findings, so scan hardened only, or
     scan both and assert a difference.
2. **Image job.** Build `app/api`, then `trivy image` (fail on
   CRITICAL/HIGH with a fix available). Keep provenance in CI (it is
   disabled only for the local kind build).
3. **e2e job on kind (`helm/kind-action`, pinned).**
   - `make cluster kyverno policies`, then
     `vulnerable` + `verify-all --expect exploitable`, then
     `hardened` + `verify-all --expect blocked`, plus `smoke`,
     `verify-admission` and `reports`.
   - Falco first needs a check that `modern_ebpf` works on GitHub-hosted
     runners (kernel version, BTF). If it does, add `verify-detection`;
     otherwise make that step optional and document why.
   - Watch the job time: Calico plus image pulls take several minutes. Cache
     images if possible.
4. **Hygiene.** Pin actions by commit SHA (the same supply-chain argument as
   scenario 6), set `permissions: contents: read`, and use Dependabot for
   actions and base images.

Add a LEARNING entry per commit, and confirm CI green on GitHub after each
push.

## Then: Phase 7 — README, threat model, INTERVIEW.md

- **README rewrite.**
  - An architecture diagram (web → api → db, the hardened layers, Kyverno
    and Falco around them).
  - A results table generated from `verify-all` and `verify-detection`
    output.
  - How to read the exit codes.
  - What is simulated: `kubectl exec` stands in for RCE, `kind load` for a
    registry push.
- **`docs/THREAT-MODEL.md`.**
  - Assets: DB password, node, Kubernetes API.
  - Attacker positions: RCE in web, `view` user, push access to the
    registry.
  - STRIDE per tier, the MITRE ATT&CK / Kubernetes threat matrix mapping
    for scenarios 1–7.
  - Residual risks, taken from the "honest limits" above.
- **`docs/INTERVIEW.md`** (like in SecScan). A 2-minute pitch, the story
  of each scenario (misconfig → impact → fix → policy → detection), the
  debugging war stories with evidence:
  - the UDP `connect()` false alert;
  - the shadowing rule (`rule_matching`);
  - `kind load` and digests, BuildKit provenance;
  - the reports controller stalling at its memory limit;
  - busybox `argv[0]`;
  - `grep` under `pipefail`.

  Plus the strongest interview questions from `LEARNING.md`.

## Later: Scenario 7 — SecScan (SSRF → Kubernetes API)

SecScan (already running in `secscan` with its own NetworkPolicy and a
Cosign `NamespacedImageValidatingPolicy`) becomes scenario 7. The attack:
a URL fetched by SecScan is pointed at `https://kubernetes.default.svc`
(with a mounted token) or at other internal Services.

Defenses:
- no token automount;
- an egress NetworkPolicy without the API server;
- the Falco outbound rule generalized to SecScan;
- the Kyverno **`ImageValidatingPolicy`** for its Cosign signature, signed
  in SecScan's CI and pulled from GHCR. That is where signature
  verification fits, since a local `kind load` image has nowhere to store a
  signature.

Coordinate with the SecScan repo: the lab must not change its namespace
without that project's manifests.

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
- Edit shell scripts with an editor, not `awk`/`sed` generators: `\n` and
  `\0` get expanded (it produced a NUL byte in a README once).
- A Kyverno controller with `Completed`/exit 0 restarts is losing its
  leader lease. Check `memory.events` of its cgroup, not just the pod
  status.

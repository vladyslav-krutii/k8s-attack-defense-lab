# Next session handoff

_Last updated: 2026-11-22. **The project is DONE**: Phases 0–7 are
complete. What is left is optional (see "Optional extensions" below)._

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
  new Falco rules, plus the api image (now `0.2.1`), which reads
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
- **Phase 6 done (CI)** and **Phase 7 done (docs)**: see the sections
  below. Full [README](../README.md), [threat model](THREAT_MODEL.md),
  [interview notes](INTERVIEW.md).
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
make vulnerable && make verify-detection && make smoke && bash scripts/verify-all.sh --expect exploitable
make hardened   && make verify-detection && make smoke && bash scripts/verify-all.sh --expect blocked
make policy-test verify-admission reports
make ci-static scan-image    # the CI static and image jobs, locally
```

`make verify-detection` has to run right after a deploy, before anything
else execs into the pods: it measures the start-up window from the
namespace creation, and the first CI run failed exactly on that. Scenario 6's `run.sh` needs
`docker` and `kind` on the host.

## Phase 6 — CI: DONE

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every
push to `main`, on PRs and on demand. Every job calls the same make targets
a person runs locally.

| Job | What | Time |
|---|---|---|
| `static` | `make lint` (kustomize + kubeconform, 63/63), `policy-test` (105/105), `shellcheck`, `falco-validate`, `secrets-scan` (gitleaks over the history), `scan-config` | ~20 s |
| `image` | `make scan-image`: push to a throwaway registry, trivy by digest, SBOM artifact | ~40 s |
| `e2e` | kind + Calico, Kyverno + policies, Falco; vulnerable (verify-detection, `verify-all --expect exploitable`), hardened (verify-detection, smoke, `verify-all --expect blocked`), `verify-admission`, `reports` | ~5 min |

**First green run of all three jobs:** run 44935042747 on `b9f5c59`.

- **How the deliberately bad overlay is handled.** Opposite gates. Hardened
  must be clean (trivy config MEDIUM+, `verify-all --expect blocked`).
  Vulnerable must stay bad (trivy config must report HIGH findings,
  currently 11; `verify-all --expect exploitable`). A "clean" vulnerable
  overlay means the demo or the scanner broke.
- **Accepted findings** are listed with a reason in
  [`.trivyignore.yaml`](../.trivyignore.yaml): KSV-0125 for the local api
  and nginxinc images. LOW findings (UID > 10000) are printed, not gated.
- **Supply chain of the CI itself.**
  - Only GitHub's own actions are used (`checkout`, `upload-artifact`),
    pinned by commit SHA.
  - Tools are release binaries with verified SHA-256
    ([`scripts/install-ci-tools.sh`](../scripts/install-ci-tools.sh)).
  - kubeconform schemas are pinned to commits, Falco and registry images
    to digests.
  - Permissions: `permissions: {}` for the workflow, `contents: read` per
    job, and `persist-credentials: false`.
- **Found on the way.**
  - The api image shipped npm with 6 fixable HIGH CVEs. npm, corepack and
    yarn are now removed from the runtime stage (image `0.2.1`).
  - 28 shellcheck findings: one real printf bug was fixed, and each
    intentional SC2016 has its reason next to it.
  - The first e2e run failed because verify-all ran before
    verify-detection and polluted its start-up window. The steps are now
    in the right order.
  - A later e2e run (docs-only commit `54222dc`) failed in
    `make policies`. On a fresh cluster Kyverno's pods were Ready, but its
    policy-validation webhook did not answer yet. `make policies` now
    retries the idempotent apply for up to 90 s.
- **Falco on GitHub-hosted runners: works.** `modern_ebpf` starts, and all
  six rules match the documented matrix on both overlays.
- **Not done, deliberately.** The images are not pushed to a real registry
  and not signed with Cosign. That belongs to scenario 7 (SecScan on GHCR).
  Builds are not byte-reproducible across machines (the CI digest differs
  from the local one), so scanning has to name the exact digest.

## Phase 7 — docs: DONE

A reviewer understands the project in two minutes and can check every
claim. Format reference: the SecScan repo.

| Document | What |
|---|---|
| [`README.md`](../README.md) | pitch; scenario table (misconfiguration → attack → hardened layer → Falco rule → verify target); Mermaid architecture (checked on GitHub: renders in full); defense layers linked to files; results of CI run 44936598909; exit codes, what is simulated, out of scope; quickstart with PowerShell/WSL notes; CI jobs with local equivalents |
| [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) | STRIDE per trust boundary: threat → control → where → how verified (verify-N, verify-admission, kyverno test, verify-detection, CI job; "review only" where nothing checks it); the controls themselves as targets; accepted risks and known limits |
| [`docs/INTERVIEW.md`](INTERVIEW.md) | Ukrainian: 3-minute story, scenarios in one table, the six hardest findings, 20 Q&A, 5-minute demo script, honest limits |

- **Checked on the cluster on the way (2026-11-22, hardened).** In-cluster
  web → `db:5432` is BLOCKED, but `kubectl port-forward deploy/db` reaches
  Postgres: the kubelet enters the pod's netns, so NetworkPolicy never sees
  it. `lab:developers` cannot `create pods/portforward`. Recorded as an
  accepted risk.
- **Repo metadata.** The description and topics on GitHub match the README.
- **The docs rule stays.** Numbers come from a named CI run; re-run and
  update them together if anything changes.

## Optional extensions

None of these is required; each is a self-contained next step.

1. **Scenario 7: SecScan SSRF → Kubernetes API.** SecScan already runs in
   the `secscan` namespace with its own NetworkPolicy and a Cosign
   `NamespacedImageValidatingPolicy`. The attack: SecScan fetches a URL
   pointed at `https://kubernetes.default.svc` (with a mounted token) or at
   other internal Services. Defenses: no token automount, an egress policy
   without the API server, the Falco outbound rule generalized to SecScan,
   and a Kyverno `ImageValidatingPolicy` for its Cosign signature (signed
   in SecScan's CI, pulled from GHCR). **Coordinate with the SecScan repo;
   the lab must not change the `secscan` namespace on its own.**
2. **Cosign verification for the lab's own api image.** A local registry
   reachable by both the kind nodes and Kyverno (kind's
   `containerdConfigPatches` mirror + a `registry:3` container on the kind
   network). Build → push → `cosign sign` (key pair for the lab, or keyless
   in CI) → `ImageValidatingPolicy` with `attestors`. This removes the
   KSV-0125 entry from `.trivyignore.yaml` and closes "digest says what,
   not who" from scenario 6.
3. **Falcosidekick alerts.** Forward Falco alerts to a webhook, Slack or a
   local Loki/Grafana; add a `make` target that shows one alert arriving.
   Keep it local-only.
4. Smaller ideas: distroless `web` so rule 1 can stay silent on hardened;
   `make help` grouped by cluster / app / checks; Calico flow logs for
   denied flows; 3 Kyverno admission replicas with a PDB.

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

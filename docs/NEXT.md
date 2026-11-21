# Next session handoff

_Last updated: 2026-11-21. Phase 6 (CI) is done._

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
- **Falco on GitHub-hosted runners: works.** `modern_ebpf` starts, and all
  six rules match the documented matrix on both overlays.
- **Not done, deliberately.** The images are not pushed to a real registry
  and not signed with Cosign. That belongs to scenario 7 (SecScan on GHCR).
  Builds are not byte-reproducible across machines (the CI digest differs
  from the local one), so scanning has to name the exact digest.

## Next: Phase 7 — README, threat model, INTERVIEW.md

Goal: a reviewer understands the project in 2 minutes and can verify every
claim. One commit per document, plus LEARNING entries.

1. **README rewrite** (replaces the short version).
   - A pitch, then a CI badge.
   - An architecture diagram (Mermaid, renders on GitHub): web → api → db,
     the hardened layers 1–6 around them, Kyverno at admission, Falco at
     runtime.
   - The results tables: `verify-all` on both overlays, the detection
     matrix, `trivy config` counts. Each one says which CI step proves it.
   - How to read exit codes 0/1/2, what is simulated (`kubectl exec` = RCE
     foothold, `kind load` = registry push) and what is out of scope.
   - The quickstart, and the local equivalent of every CI job
     (`make ci-static`, `make scan-image`, the e2e sequence).
2. **`docs/THREAT-MODEL.md`.**
   - Scope and trust boundaries: internet → web, web → api → db, pods →
     the Kubernetes API, the node, the registry and CI.
   - Assets: the DB password, node and kubelet credentials, the Kubernetes
     API, the image supply chain.
   - Attacker positions: RCE in web, a `view` user, push access to the
     image tag, a compromised CI step.
   - STRIDE per boundary, mapped to scenarios 1–6 (and 7), MITRE ATT&CK
     and the Microsoft Kubernetes threat matrix.
   - **Residual risks**, taken from each scenario's honest limits:
     - the `/tmp` exec;
     - the app user can read its own secret file;
     - no signatures yet;
     - the infra namespaces are excluded from Kyverno;
     - the Falco logs contain command lines;
     - the shell rule fires on hardened.
3. **`docs/INTERVIEW.md`** (like in SecScan).
   - A 2-minute pitch, and a 30-second version.
   - Per scenario: misconfiguration → impact → fix → policy → detection
     → limit, in five lines.
   - Debugging stories, each with its evidence:
     - the UDP `connect()` false alert;
     - the `rule_matching: first` shadowing;
     - `kind load` and digests, BuildKit provenance;
     - the reports controller stalling at its memory limit;
     - busybox `argv[0]`;
     - `grep` under `pipefail`;
     - the order dependence of the e2e test.
   - Trade-offs to defend: audit → enforce, `secretKeyRef` enforced, a
     non-privileged Falco, fail-closed webhooks with the infra exclusions,
     the opposite CI gates.
   - The strongest questions from `LEARNING.md`, with short answers.
4. **Small polish.**
   - A CI badge in the README.
   - `make help` grouped (cluster / app / checks).
   - Check every link in the docs.

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

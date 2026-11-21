# Scenario 6: Supply chain – mutable image tags

| | |
|---|---|
| **Foothold** | Ability to publish an image under an existing name: a leaked registry token, a compromised CI job, a hijacked upstream image |
| **Misconfiguration** | Images referenced by tag (`k8s-lab/api:latest`, `postgres:17.12-alpine`, ...), `imagePullPolicy: IfNotPresent`, no digest |
| **Where** | [`k8s/overlays/vulnerable/kustomization.yaml`](../../k8s/overlays/vulnerable/kustomization.yaml) (`images:`), version tags in [`k8s/base/`](../../k8s/base/) |
| **MITRE ATT&CK** | T1525 Implant Internal Image, T1195.002 Compromise Software Supply Chain |
| **Kubernetes threat matrix** | Backdoor container, Compromised image in registry |

## Misconfiguration

```yaml
image: k8s-lab/api:latest      # or any tag: "1.2.3" is just as movable
imagePullPolicy: IfNotPresent
```

## Why it is dangerous

A tag is a pointer that the registry lets anyone with push rights move.
A digest (`@sha256:…`) is the hash of the content, so it cannot be moved.
With tags:

- **The same manifest runs different code** after the next restart, and
  there is no change in git, no `kubectl apply` and no audit event in the
  cluster.
- **Checks are applied to the wrong image.** The image that was scanned,
  reviewed or signed at build time is not necessarily the one that runs.
- **Nodes disagree.** With `IfNotPresent`, every node runs whatever it has
  cached under that tag, so two replicas of one Deployment can run
  different code. Rollbacks are guesswork.
- `:latest` is the extreme case, but `1.2.3` is mutable too: registries
  allow overwriting tags unless immutability is switched on.

## Attack (what `run.sh` shows)

Runs on the host (needs `docker` and `kind`), fully local:

1. It reads the api Deployment's image reference and the running image ID.
2. The "attacker" builds `FROM <same tag>` plus one marker file,
   `/app/TAMPERED`, tags it with **the same name**, and copies it into the
   kind nodes with `kind load`. That stands in for a push to the registry.
3. `kubectl rollout restart deploy/api` stands in for any node drain,
   eviction or scale-up. The manifest is unchanged.
4. It checks whether the new pod contains `/app/TAMPERED`.
5. It restores the genuine image and restarts api again.

| | vulnerable (`api:latest`) | hardened (`api:0.2.0@sha256:…`) |
|---|---|---|
| Deployment image after the attack | unchanged | unchanged |
| running image | the attacker's | the pinned, genuine one |
| `/app/TAMPERED` | present | absent |

Nothing is pushed to any registry, and the marker file is the only change.

## Fix (hardened, layer 6)

- **Every image pinned by digest**, written as `name:tag@sha256:digest`
  (the tag is for humans, the runtime ignores it). Third-party digests
  (Docker Hub index digests) are in the overlay's
  [`images:`](../../k8s/overlays/hardened/kustomization.yaml) and are
  updated deliberately, the way Renovate or Dependabot would.
- **The locally built api image** gets its digest at deploy time.
  `make hardened` renders the overlay through
  [`scripts/render-pinned.sh`](../../scripts/render-pinned.sh), which:
  - reads the digest that containerd on **every kind node** actually has
    (and fails if the nodes disagree);
  - registers the `name@sha256:…` reference that `kind load` does not
    create (without it the kubelet tries Docker Hub and gets
    `ErrImagePull`).

  In a real pipeline, CI pushes the image and writes its digest into the
  deployment repo.
- **Reproducible local digest**: `make build` uses `--provenance=false`.
  BuildKit's provenance attestation carries timestamps, so every build,
  even a fully cached one, got a new index digest.

## Admission (Kyverno)

- New [`require-image-digest`](../../policies/kyverno/base/require-image-digest.yaml):
  every container, init container and ephemeral container must end in
  `@sha256:<64 hex>`. Audit in vulnerable, enforce in hardened. As a
  consequence, `kubectl apply -k k8s/overlays/hardened` on its own is
  **rejected** (api has no digest), and only `make hardened` deploys it.
  That is intended.
- `disallow-latest-tag` (Phase 4) stays as the weaker, older guard.

**Not covered: who built the image.** A digest proves the bytes are the
same, not that they are trustworthy. That takes signature verification:
Cosign plus a Kyverno `ImageValidatingPolicy`. It is planned for scenario
7 (SecScan, signed in its own CI and pulled from a registry). For this
lab's api image it would need a local registry that both Kyverno and the
nodes can reach, because `kind load` has nowhere to store a signature.

## Detection

Falco does not help much here. The tampered container looks like the
genuine one at the syscall level. Detection belongs to the registry (tag
immutability, push audit logs) and to admission (digest and signature
policies). The background scan of `require-image-digest` lists every
workload that still runs by tag (`make reports`).

## Run

```bash
make vulnerable
make scenario-6
make verify-6
```

`verify.sh` checks two things:
- every container image of every Deployment is pinned by digest;
- the namespace's admission (server-side dry run, nothing created) rejects
  a pod that differs only in having a tag-only image, while it admits the
  same pod pinned by digest (the control).

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: a workload runs by tag, or the namespace admits tag-only images |
| 1 | BLOCKED: everything is pinned and admission rejects tag-only images |
| 2 | INCONCLUSIVE: the test could not run, or a probe was rejected for another reason |

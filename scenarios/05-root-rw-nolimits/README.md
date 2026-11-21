# Scenario 5: Root, writable root filesystem, no resource limits

| | |
|---|---|
| **Foothold** | Code execution in the `web` container (simulated with `kubectl exec`) |
| **Misconfiguration** | Containers run as root (web, via the scenario 1 patch) with a writable image filesystem and no CPU/memory limits |
| **Where** | By absence: [`k8s/base/`](../../k8s/base/) sets no `readOnlyRootFilesystem` and no `resources`; root comes from [`patches/01-web-privileged-hostpath.yaml`](../../k8s/overlays/vulnerable/patches/01-web-privileged-hostpath.yaml) |
| **MITRE ATT&CK** | T1105 Ingress Tool Transfer, T1496 Resource Hijacking, T1499 Endpoint Denial of Service |
| **Kubernetes threat matrix** | Writable hostPath / container filesystem, Resource hijacking |

## Misconfiguration

Nothing to point at, and that is the problem: a container without
`securityContext.readOnlyRootFilesystem` and without `resources.limits`
is the Kubernetes default.

## Why it is dangerous

- **Writable image filesystem.** After code execution, the attacker can add
  tools to `/usr/local/bin`, replace binaries or libraries, change config,
  and keep files there until the pod is recreated. As root, every path in
  the image is writable.
- **No limits.** A cgroup without `memory.max` or a CPU quota lets one
  container use every core and all the memory of the node: cryptomining,
  or a denial of service for every other pod on that node (they get
  evicted or OOM-killed instead). Requests without limits do not help: a
  request is a scheduling reservation, not a ceiling.

## Attack (what `run.sh` shows)

| Step | vulnerable | hardened |
|---|---|---|
| `id`, root FS mount flag | `uid=0`, `overlay rw` | `uid=101`, `overlay ro` |
| copy busybox to `/usr/local/bin/busybox-lab-tool`, run it | runs | `Read-only file system` |
| the same in `/tmp` | runs | **runs** (see below) |
| `memory.max`, `cpu.max` | `max`, `max 100000` | `134217728`, `20000 100000` |
| 3-second busy loop, throttled periods | 0 | ~30 |

The "tool" is the image's own busybox, renamed with a `busybox-` prefix
because busybox picks its applet from `argv[0]`. Nothing is downloaded,
and every file is removed afterwards. No memory is allocated: a real
exhaustion would hit other pods on the node, so the demo reads the cgroup
ceiling instead, and shows the CPU limit biting with a short single-core
loop.

## Fix (hardened, layer 5)

[`patches/runtime-limits.yaml`](../../k8s/overlays/hardened/patches/runtime-limits.yaml):

- `readOnlyRootFilesystem: true` on all three containers. Writable paths
  are explicit `emptyDir`s with a `sizeLimit`, found by running each image
  read-only:
  - web: `/tmp`;
  - api: nothing;
  - db: `/var/run/postgresql`, plus the existing data dir.
- CPU and memory **requests and limits** on every container.
- Non-root comes from layer 1.

**Honest limit.** The `/tmp` emptyDir stays writable *and executable*:
Kubernetes cannot mount an emptyDir `noexec`. A read-only root FS stops
changes to the image, but not running a dropped binary from a scratch
volume. What covers that:
- an image without a shell or busybox (distroless);
- Falco runtime detection (below);
- in hardened, the dropped tool still runs as UID 101 with no
  capabilities, inside the CPU and memory limits.

## Admission (Kyverno)

- New [`require-readonly-rootfs`](../../policies/kyverno/base/require-readonly-rootfs.yaml)
  (containers and init containers; `kubectl debug` containers are exempt).
- [`require-resource-limits`](../../policies/kyverno/base/require-resource-limits.yaml)
  moves from audit-only to **enforce** in hardened, now that the workloads
  have limits (the Phase 4 temporary exception is gone).

## Run

```bash
make vulnerable
make scenario-5
make verify-5
```

`verify.sh` reads what the kernel enforces inside web, api and db: `id -u`,
the `/` mount flags in `/proc/mounts`, and `memory.max` / `cpu.max` from
cgroup v2. It does not read the pod spec.

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: some container runs as root, has a writable root FS, or lacks a CPU or memory limit |
| 1 | BLOCKED: all three are non-root, read-only and limited |
| 2 | INCONCLUSIVE: the test could not run |

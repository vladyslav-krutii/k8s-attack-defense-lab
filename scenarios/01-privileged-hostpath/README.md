# Scenario 1: Privileged pod + hostPath → access to the node

| | |
|---|---|
| **Foothold** | Code execution in the `web` container (simulated with `kubectl exec`) |
| **Misconfiguration** | `privileged: true`, `runAsUser: 0`, node `/` mounted at `/host` via `hostPath` |
| **Where** | [`k8s/overlays/vulnerable/patches/01-web-privileged-hostpath.yaml`](../../k8s/overlays/vulnerable/patches/01-web-privileged-hostpath.yaml) |
| **MITRE ATT&CK** | T1611 Escape to Host |
| **Kubernetes threat matrix** | Privileged container, Writable hostPath mount |

## Misconfiguration

```yaml
securityContext:
  privileged: true
  runAsUser: 0
volumes:
  - name: host-root
    hostPath: { path: /, type: Directory }
```

How it gets there in real life: a log shipper or monitoring agent "needs" host
access, or someone debugging a node adds `privileged: true` and never removes it.

## Why it is dangerous

A container is just a process with namespaces, cgroups, dropped capabilities
and a seccomp profile around it. `privileged: true` removes most of that
isolation: the process gets **all** Linux capabilities and **all** host
devices, without seccomp/AppArmor confinement. A `hostPath` mount of `/` hands
over the node's filesystem directly. Together they are a container escape
that needs no exploit at all.

On a real node, that filesystem holds:

- the kubelet's client certificate (the node's identity to the API server),
- the service account tokens and mounted Secrets of **every pod on the node**,
- containerd state, other containers' filesystems, `/etc`, SSH keys.

One compromised pod becomes a compromised node, and from the node, every
workload on it.

## Attack (what `run.sh` shows)

| Step | Observation |
|---|---|
| `id` | `uid=0(root)` |
| `CapEff` in `/proc/self/status` | `000001ffffffffff`, every capability |
| `cat /host/etc/hostname` | `k8s-lab-worker`, the **node's** name, not the pod's |
| `ls /host/var/lib/kubelet/pki/` | kubelet client certificate and key are there |
| count of `token` files under `/host/var/lib/kubelet/pods` | service account tokens of every pod on the node |

The script stops at read-only listing on purpose. It does not print secret
material, write to the node or run `chroot /host`, which would be a root shell
on the node.

## Impact

Full compromise of the worker node and of every workload scheduled on it,
plus a foothold to attack the API server with the kubelet's credentials.

## Fix (Phase 3)

- Pod Security Admission `enforce: restricted` on the namespace. It rejects
  privileged pods, `hostPath` volumes and root users at admission time.
- Explicit `securityContext`: `runAsNonRoot: true`,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `seccompProfile: RuntimeDefault`.
- Phase 4: Kyverno policies as a second admission layer with clearer
  messages, and to cover what PSA cannot express.

## Detection (Phase 4)

- **Falco**: rules for a privileged container starting, a sensitive host
  path being mounted, and reads of kubelet credentials or other pods' tokens.
- **Admission audit**: the `audit: restricted` label already records PSA
  violations in the API server audit log.
- **Trivy / kubescape** flag `privileged` and `hostPath` in manifests before
  they reach the cluster (Phase 6, CI).

## Run

```bash
make vulnerable
make scenario-1
make verify-1
```

`verify.sh` runs two checks:

1. **Current state.** It compares `/host/etc/hostname` inside the container
   with the pod's `spec.nodeName`. A pod's own `/etc/hostname` is the pod
   name, so a match can only come from the node's filesystem.
2. **Guardrail.** It sends a privileged pod with a `hostPath: /` volume using
   `kubectl apply --dry-run=server`. The request goes through every admission
   check (Pod Security Admission now, Kyverno from Phase 4), but nothing is
   stored or run. Removing the bad patch is not enough on its own: if the
   namespace still admits such a pod, anyone with `create pods` (see
   scenario 2) or a careless deploy brings the escape back.

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: the web container reads the node's filesystem, or admission would accept a privileged hostPath pod |
| 1 | BLOCKED |
| 2 | INCONCLUSIVE: the test could not run |

`make` turns every non-zero exit into its own error code. Run
`bash scenarios/01-privileged-hostpath/verify.sh; echo $?` to see the exact one.

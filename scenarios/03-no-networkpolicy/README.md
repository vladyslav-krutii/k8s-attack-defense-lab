# Scenario 3: No NetworkPolicy → lateral movement from web to the database

| | |
|---|---|
| **Foothold** | Code execution in the `web` container (simulated with `kubectl exec`) |
| **Misconfiguration** | No NetworkPolicy in the namespace: every pod can reach every pod on every port |
| **Where** | Absence, see the note in [`k8s/overlays/vulnerable/kustomization.yaml`](../../k8s/overlays/vulnerable/kustomization.yaml) |
| **MITRE ATT&CK** | T1046 Network Service Discovery (lateral movement inside the cluster network) |
| **Kubernetes threat matrix** | Cluster internal networking |

## Misconfiguration

Nothing to show. Kubernetes networking is **allow-all by default**: unless a
NetworkPolicy selects a pod, all ingress and egress traffic to and from it is
allowed. The intended flow is

```
browser -> web:8080 -> api:3000 -> db:5432
```

but the network also allows `web -> db:5432` directly.

## Why it is dangerous

Tiers exist so that each layer only talks to the next one. The api tier is
where input validation and parameterized SQL live. With a flat network, a
compromise of the internet-facing pod skips all of that and goes straight to
the data. In real clusters the same flat network also exposes other teams'
services, internal admin endpoints, the cloud metadata API and the
Kubernetes API server.

It is common because it is a misconfiguration by **absence**: nothing in any
manifest looks wrong, and no scanner of a single Deployment will complain.

## Attack (what `run.sh` shows)

| Step | Observation |
|---|---|
| `wget http://api:3000/healthz` | `{"status":"ok"}`: the intended path works (control) |
| `nc -z db 5432` | TCP connection **open** from web to the database |
| 8-byte PostgreSQL `SSLRequest` via `nc` | reply `N`: it really is PostgreSQL, accepting unencrypted connections |
| `kubectl get networkpolicy` | none |

Only busybox tools already in the image are used. The only bytes sent to the
database are the standard 8-byte handshake; there is no login attempt and no
query.

## Impact

The database is one hop from the internet-facing tier. Together with
scenario 2 (the password from `db-credentials`), an attacker in `web` can log
in to PostgreSQL directly and read or modify all data, bypassing the
application.

## Fix (Phase 3)

- **Default deny** for ingress and egress in the namespace
  (`podSelector: {}` with no rules).
- Explicit allows that mirror the architecture, nothing more:
  - `web` ingress on 8080 (from port-forward and the smoke test);
  - `web` egress → `api:3000`; `api` ingress from `web` only;
  - `api` egress → `db:5432`; `db` ingress from `api` only;
  - DNS egress to CoreDNS (UDP/TCP 53) for pods that resolve names.
- Calico enforces it (proven in Phase 0 by `make verify-netpol`).

## Detection (Phase 4)

- **Falco**: outbound connection from `web` to anything other than `api`
  (unexpected outbound connection rule).
- **Calico flow logs** (Goldmane/Whisker, optional) show denied flows once
  policies exist, so blocked lateral movement attempts become visible.
- **kubescape / kube-linter** in CI: workloads not selected by any
  NetworkPolicy.

## Run

```bash
make vulnerable
make scenario-3
make verify-3
```

`verify.sh` first checks the **legitimate** path `web -> api:3000`. If that
fails too (DNS blocked, api down, policy too strict), a failed connection to
the database proves nothing, and the result is INCONCLUSIVE, not BLOCKED.

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: web reaches `db:5432` |
| 1 | BLOCKED: web cannot reach `db:5432`, while `web -> api` works |
| 2 | INCONCLUSIVE: the test could not run, or the control check failed |

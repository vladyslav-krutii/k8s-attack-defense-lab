# Scenario 2: Over-permissive RBAC + auto-mounted token → reading Secrets

| | |
|---|---|
| **Foothold** | Code execution in the `web` container (simulated with `kubectl exec`) |
| **Misconfiguration** | ServiceAccount `web` bound to the built-in `edit` ClusterRole; token auto-mounted into the pod |
| **Where** | [`k8s/overlays/vulnerable/rbac-web.yaml`](../../k8s/overlays/vulnerable/rbac-web.yaml), [`patches/02-web-serviceaccount.yaml`](../../k8s/overlays/vulnerable/patches/02-web-serviceaccount.yaml) |
| **MITRE ATT&CK** | T1552.007 Unsecured Credentials: Container API |
| **Kubernetes threat matrix** | Access container service account, List K8s secrets |

## Misconfiguration

```yaml
kind: RoleBinding
subjects: [{ kind: ServiceAccount, name: web, namespace: demo }]
roleRef:  { kind: ClusterRole, name: edit }
---
# Deployment web
serviceAccountName: web
automountServiceAccountToken: true   # also the default
```

How it gets there in real life: the app needs to read one ConfigMap, gets
`forbidden`, and someone binds a built-in role "to make it work". Helm charts
that create broad roles by default are another common source.

## Why it is dangerous

Two separate mistakes combine:

1. **Auto-mounted token.** By default every pod gets an API token for its
   service account at `/var/run/secrets/kubernetes.io/serviceaccount/`.
   nginx never calls the Kubernetes API, so the token is useless to the app
   but valuable to anyone who gets code execution.
2. **Over-permissive role.** `edit` grants read and write on Secrets,
   creating pods, `pods/exec` and editing Deployments. A namespace-scoped
   binding is not safe either: everything valuable for this app lives in this
   namespace.

A Secret is base64-encoded, not encrypted. Anyone allowed to `get secrets`
reads the plain value. With `create pods` the attacker can also start a new
pod that mounts any Secret, or that runs privileged where admission allows it
(scenario 1).

## Attack (what `run.sh` shows)

| Step | Observation |
|---|---|
| `ls /var/run/secrets/kubernetes.io/serviceaccount/` | `ca.crt`, `namespace`, `token` |
| `POST selfsubjectreviews` | `system:serviceaccount:demo:web`: the API accepts the token |
| `GET /api/v1/namespaces/demo/secrets` | `db-credentials` |
| `GET .../secrets/db-credentials` | password decoded; shown masked as `lab***` |
| `kubectl auth can-i --list --as=...` | defender's view: `secrets`, `pods`, `pods/exec`, `deployments` with write verbs |

Only `curl` (already in the image) is used. The script prints the password
masked and makes no write calls.

## Impact

Every credential in the namespace is exposed (here the database password, see
scenario 3). With `edit`, the attacker can persist by changing Deployments and
move to other pods through `pods/exec`, without any network access to them.

## Fix (Phase 3)

- `automountServiceAccountToken: false` on the ServiceAccount and the pod.
  `web` needs no token at all.
- No RoleBinding for `web`. If a workload does need the API, use a dedicated
  Role with only the needed verbs on named resources (`resourceNames`), never
  `edit`, `admin` or wildcards.
- Egress NetworkPolicy so `web` cannot reach the API server at all
  (defense in depth).
- Longer term: Secrets from an external store (External Secrets, Vault) and
  encryption at rest in etcd.

## Detection (Phase 4)

- **Falco**: a process other than the expected one reads the service account
  token file; outbound connection from `web` to the API server.
- **API server audit log**: `get`/`list` on `secrets` by
  `system:serviceaccount:demo:web` is anomalous for a web server.
- **Kyverno / kubescape**: flag bindings to `edit`/`admin`/`cluster-admin`
  for workload service accounts, and pods that auto-mount tokens.

## Run

```bash
make vulnerable
make scenario-2
make verify-2
```

`verify.sh` replays the real attack path from **inside** the pod: is a token
mounted, and does it return HTTP 200 for `db-credentials`? `kubectl auth can-i`
from outside is not enough, because RBAC may be wrong while no token is
mounted, or the reverse. Only the combination is exploitable.

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: HTTP 200 on the Secret |
| 1 | BLOCKED: no token, HTTP 401/403, or API server unreachable |
| 2 | INCONCLUSIVE: the test could not run |

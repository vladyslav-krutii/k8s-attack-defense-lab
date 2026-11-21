# Scenario 4: Credentials in environment variables and ConfigMaps

| | |
|---|---|
| **Foothold** | Read-only cluster access (the built-in `view` role), or any `exec` / code execution in an app container |
| **Misconfiguration** | The DB password is copied into a ConfigMap and passed to `api` as an env var; `db` gets it as a `secretKeyRef` env var |
| **Where** | [`k8s/overlays/vulnerable/kustomization.yaml`](../../k8s/overlays/vulnerable/kustomization.yaml) (`configMapGenerator`), [`patches/04-api-password-in-configmap.yaml`](../../k8s/overlays/vulnerable/patches/04-api-password-in-configmap.yaml), [`k8s/base/db.yaml`](../../k8s/base/db.yaml) |
| **MITRE ATT&CK** | T1552.001 Credentials in Files, T1552.007 Container API |
| **Kubernetes threat matrix** | Application credentials in configuration files |

## Misconfiguration

```yaml
# ConfigMap (generated)                  # Deployment api
data:                                    env:
  PGPASSWORD: lab-only-...                 - name: PGPASSWORD
                                             valueFrom:
                                               configMapKeyRef: {name: api-config, key: PGPASSWORD}
# Deployment db (the base, "the default way")
env:
  - name: POSTGRES_PASSWORD
    valueFrom: {secretKeyRef: {name: db-credentials, key: password}}
```

How it gets there in real life: all settings go into one ConfigMap, "it is
just config". Or the Secret is used correctly but injected with
`secretKeyRef`, which every tutorial shows first.

## Why it is dangerous

Two different problems:

1. **A ConfigMap is not a Secret.** RBAC treats them differently on
   purpose. The built-in `view` role reads ConfigMaps, pods and
   Deployments, but *no* Secrets, and it is handed out freely: to
   developers, dashboards, CI and monitoring. A password in a ConfigMap (or
   as a literal `env.value` in a pod spec) is readable by all of them. It is
   also printed in full by `kubectl describe configmap`, and it is stored in
   git next to the manifests.
2. **An env var is copied everywhere.** Even from a Secret
   (`secretKeyRef`), the value becomes part of the process environment:
   - inherited by every child process: shells, `npm` scripts, crash
     reporters, debuggers;
   - visible in `/proc/<pid>/environ` to any process of the same user;
   - printed by `printenv` in every `kubectl exec` session (the runtime
     injects the container env into exec'd processes);
   - often dumped by error pages and diagnostics ("print config on
     startup").

   An env var also never changes after the process starts, so rotating the
   Secret does nothing until a restart.

## Attack (what `run.sh` shows)

| Step | Observation (vulnerable) |
|---|---|
| `kubectl auth can-i get secrets --as-group=lab:developers` | `no`: `view` hides Secrets |
| `kubectl get configmaps` as that developer | `api-config-…/PGPASSWORD=lab***` |
| `kubectl describe pod` as that developer | points straight at the ConfigMap key |
| `kubectl exec deploy/api -- printenv`, same for db | `PGPASSWORD=lab***`, `POSTGRES_PASSWORD=lab***` |
| `/proc/1/environ` of the Node process | `PGPASSWORD=lab***` |

Read-only, no writes. Every value is masked (first three characters and
the length).

(Postgres overwrites its own `/proc/1/environ` when it sets its process
title, so the `/proc` step only uses api. `printenv` still shows the db
password, because a new process gets the container env from the runtime.)

## Fix (hardened, layer 4)

[`patches/secrets-as-files.yaml`](../../k8s/overlays/hardened/patches/secrets-as-files.yaml):

- The Secret is mounted as a **read-only volume**, `defaultMode: 0440`
  (owner root, group = the pod's `fsGroup`, nothing for others).
- `api` reads `PGPASSWORD_FILE` ([`server.ts`](../../app/api/src/server.ts)
  reads it for every new DB connection, so a rotated Secret is picked up
  without a restart). `db` uses `POSTGRES_PASSWORD_FILE`, which the postgres
  image supports.
- No credential env vars at all, and no ConfigMap with a password.

An attacker with code execution *as the app user* can still read the file:
the app has to read it, too. The gain is everything else. The password is
no longer in `view`, git, `describe`, child processes, crash dumps or
`printenv`, and the Secret can be rotated. Getting it out of the pod
entirely needs workload identity or short-lived database credentials
(Vault database secrets engine, cloud IAM auth).

## Admission (Kyverno)

- [`disallow-secrets-in-env`](../../policies/kyverno/base/disallow-secrets-in-env.yaml):
  no literal value for credential-like names (`*_FILE` paths are fine), no
  `secretKeyRef`, no `envFrom.secretRef`.
- [`disallow-secrets-in-configmaps`](../../policies/kyverno/base/disallow-secrets-in-configmaps.yaml):
  no credential-like ConfigMap keys.

Audit in vulnerable (shows up in `make reports`), enforce in hardened.
Trade-off: `secretKeyRef` is everywhere in public Helm charts. Enforcing it
cluster-wide would start in Audit, with exceptions per chart.

## Run

```bash
make vulnerable
make scenario-4
make verify-4
```

`verify.sh` compares against the real password from the Secret (read as
admin), not against variable names, so a renamed variable still counts.

| Exit code | Meaning |
|---|---|
| 0 | EXPLOITABLE: the password is readable with `view`, or is in the api/db environment |
| 1 | BLOCKED: neither, and api still authenticates to the database |
| 2 | INCONCLUSIVE: the test could not run, or `view` can read Secrets (meaningless test) |

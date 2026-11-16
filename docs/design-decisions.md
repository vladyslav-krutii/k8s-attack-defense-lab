# Design decisions and trade-offs

Short records of decisions that are not obvious from the manifests alone.
Each entry: the decision, why, what it costs, and how the cost is covered.

## Kyverno webhooks are fail-closed, infrastructure namespaces are excluded

**Decision.** Kyverno's admission webhooks keep the default
`failurePolicy: Fail`. Four infrastructure namespaces never reach the webhook:
`kube-system`, `calico-system`, `tigera-operator` and `local-path-storage`
([`cluster/kyverno/values.yaml`](../cluster/kyverno/values.yaml)). Kyverno's
own namespace, `kyverno`, is excluded by the chart (`excludeKyvernoNamespace: true`).

**Why fail-closed.** With `Ignore`, any Kyverno outage, whether a crash, an
OOM kill or an attacker deleting the pod, silently turns every policy off.
Fail-closed means "no decision, no admission".

**Why the exclusions.** The lab runs a single Kyverno admission replica. While
it is down, fail-closed would also reject the pods the cluster needs to
recover. Calico is the concrete deadlock: Kyverno needs pod networking to
start, pod networking needs `calico-node`, and a `calico-node` pod that has to
be recreated would wait for Kyverno.

**Cost.** Nothing in the excluded namespaces is checked by Kyverno. A
privileged `hostPath` pod in `kube-system` is admitted. (In kind, these
namespaces are not labelled for Pod Security Admission either.) The
exclusion list is effectively an allow-list for anyone who can write there.

**How the cost is covered: RBAC.** The exclusion is acceptable only if
creating or changing workloads in those namespaces is limited to cluster
administrators.

- Never bind workload service accounts to roles with `create`/`update` on
  pods, Deployments, DaemonSets, Jobs or CronJobs in these namespaces. That
  includes ClusterRoleBindings to `edit`, `admin` or `cluster-admin`, which
  apply in every namespace.
- Check it:

  ```bash
  for ns in kube-system calico-system tigera-operator local-path-storage kyverno; do
    for sa in web api db default; do
      echo "$ns demo:$sa $(kubectl --context kind-k8s-lab auth can-i create pods \
        -n "$ns" --as=system:serviceaccount:demo:$sa)"
    done
  done
  ```

  Expected: `no` everywhere, including on the vulnerable overlay. Scenario 2's
  `edit` binding is a RoleBinding, so it is limited to `demo`. At the time of
  writing, only `system:masters` and `kubeadm:cluster-admins` are bound to
  `cluster-admin`.
- Production adds more on top: at least 3 Kyverno admission replicas, a
  PodDisruptionBudget, and alerts on Kyverno availability. Detection also
  covers the excluded namespaces: Falco (Phase 4) watches every container on
  the node, whatever its namespace.

# Custom Falco rules

[`lab-rules.yaml`](lab-rules.yaml) adds three rules on top of Falco's stock
ruleset. `make falco` loads them through the chart's `customRules` value
(mounted as `/etc/falco/rules.d/lab-rules.yaml`). `make verify-detection`
proves they work.

| Rule | Catches | Fires on |
|------|---------|----------|
| Lab Shell Spawned Without Terminal | a shell in an app pod with no TTY, started through the exec API or by the app process itself (RCE) | every scenario (`kubectl exec deploy/web -- sh -c id`) |
| Lab Read Of Kubernetes Credentials | reads of the pod's service account token (app namespaces), the kubelet PKI, the kubelet's pod directory or other pods' tokens through a hostPath | scenario 1 (`/host/var/lib/kubelet/pki`, `/host/var/lib/kubelet/pods`), scenario 2 (`cat .../serviceaccount/token`) |
| Lab Unexpected Outbound Connection From Web | a successful or in-progress TCP `connect()` from web to anything except a ClusterIP on port 3000 (api) or 53 (DNS) | scenario 3 (`db:5432`), scenario 2 (API server `10.96.0.1:443`) |

## Expected results

```text
                          vulnerable   hardened
shell without terminal    fires        fires
credentials read          fires        silent  (no token mounted, no hostPath)
unexpected outbound       fires        silent  (see below)
```

The shell rule still fires on hardened, and that is intended. Pod hardening
does not take away a cluster admin's `pods/exec` right or the shell in the
nginx image, so the shell really runs and should be reported. To make it
silent, the image would need no shell at all (distroless).

`make verify-detection` also checks for false positives: no lab alert while
the app starts (Postgres `initdb`, the nginx entrypoint, probes) or while
`scripts/smoke.sh` sends normal traffic through web → api → db.

Rule 3 is silent on hardened for a specific reason. The NetworkPolicy drops
the packets, so busybox `nc` (a blocking `connect()`) times out and never
counts. Scenario 2 stops before its `curl`, because no token is mounted. A
**non-blocking** client is different: `curl` or Node get `EINPROGRESS`
before the drop, so the rule still fires. That is intended, because an
attempt to leave web is a sign of compromise even when the attempt is
blocked. For example, `kubectl exec deploy/web -- curl -m 3
https://10.96.0.1` on hardened raises one alert.

## Things that bit us

- **`rule_matching: first` (the default) hides rules.** The stock rule
  "Unexpected connection to K8s API Server from container" is loaded first.
  It matched web → API server, and the lab rule never got to see the event.
  [`cluster/falco/values.yaml`](../../cluster/falco/values.yaml) sets
  `rule_matching: all`. The cost is more CPU per event.
- **Exit-only events.** Falco 0.45 rules have no `evt.dir`. Success is
  `evt.rawres >= 0` (or `fd.num >= 0` for opens).
- **The stock `outbound` macro skips RFC 1918 destinations**, which means
  everything inside the cluster, so the lab rule uses its own condition.
- **A UDP `connect()` is not traffic.** musl's `getaddrinfo()` connects UDP
  sockets in two places: to `127.0.0.1:65535` / `::1` (the `AI_ADDRCONFIG`
  check), and to every resolved address to pick a source address (RFC 6724
  sorting), e.g. `10.96.0.1:443` right before curl's real TCP connection. No packet is sent. The first version alerted
  on these as `l4=udp`, so rule 3 now counts TCP connects only. UDP egress
  is left to the default-deny NetworkPolicy.
- **runc touches the service account mount** while it creates a container.
  Processes named `runc*` are excluded.
- **`proc.pname` can be `<NA>`**, because least-privileged Falco cannot walk
  the host process tree. The macro `container_entrypoint` treats a missing
  parent like the runtime.
- **Two nodes share one kernel in kind.** Both Falco pods see every syscall,
  so stock rules can alert twice. Only the Falco pod on the node that runs
  the pod resolves Kubernetes metadata, and the lab rules require it, so
  they alert once.
- **Secrets in alert output.** A scenario 2 `curl` command line contains the
  bearer token. Only the shell rule prints `proc.cmdline`; the other two
  print just the process name.

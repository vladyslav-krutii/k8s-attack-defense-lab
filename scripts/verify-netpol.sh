#!/usr/bin/env bash
# Proves that the CNI actually ENFORCES NetworkPolicy.
#
# Why this exists: the API server accepts NetworkPolicy objects even when the
# CNI ignores them. "kubectl apply" succeeding proves nothing - only traffic
# being dropped does. So we test three states:
#   1. no policy            -> connection must succeed (baseline)
#   2. default-deny ingress -> connection must be blocked
#   3. explicit allow rule  -> connection must succeed again
set -euo pipefail

NS=netpol-test
IMAGE=busybox:1.37

# Always talk to the lab cluster, whatever the current kubectl context is.
kubectl() { command kubectl --context "${KUBE_CONTEXT:-kind-k8s-lab}" "$@"; }

cleanup() { kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null; }
trap cleanup EXIT

# Returns 0 if the client pod can fetch the server's index page within 3s.
can_connect() {
  kubectl exec -n "$NS" client -- wget -q -T 3 -O /dev/null http://server:8080 2>/dev/null
}

# expect <reachable|blocked> <description>
# Retries for ~20s because policy programming on the node is asynchronous.
expect() {
  local want=$1 desc=$2
  for _ in $(seq 1 10); do
    if can_connect; then got=reachable; else got=blocked; fi
    if [ "$got" = "$want" ]; then
      echo "PASS: $desc ($got)"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: $desc (expected $want, got $got)"
  exit 1
}

echo "==> Creating test namespace and pods"
kubectl create namespace "$NS"
kubectl apply -n "$NS" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: server
  labels: {app: server}
spec:
  containers:
    - name: httpd
      image: $IMAGE
      command: ["sh", "-c", "echo ok > /tmp/index.html && httpd -f -p 8080 -h /tmp"]
---
apiVersion: v1
kind: Service
metadata:
  name: server
spec:
  selector: {app: server}
  ports:
    - port: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  labels: {app: client}
spec:
  containers:
    - name: sh
      image: $IMAGE
      command: ["sleep", "3600"]
EOF
kubectl wait -n "$NS" --for=condition=Ready pod/server pod/client --timeout=120s

echo "==> 1/3 Baseline: no NetworkPolicy"
expect reachable "client -> server without any policy"

echo "==> 2/3 Applying default-deny ingress"
kubectl apply -n "$NS" -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}          # empty selector = every pod in the namespace
  policyTypes: ["Ingress"] # no ingress rules listed = deny all ingress
EOF
expect blocked "client -> server with default-deny"

echo "==> 3/3 Applying explicit allow for app=client"
kubectl apply -n "$NS" -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-client-to-server
spec:
  podSelector:
    matchLabels: {app: server}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: client}
      ports:
        - port: 8080
EOF
expect reachable "client -> server with allow rule"

echo
echo "NetworkPolicy is enforced by the CNI."

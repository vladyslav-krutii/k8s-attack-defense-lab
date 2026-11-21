#!/usr/bin/env bash
# Vulnerability scan of the api image BY DIGEST, the way a real pipeline does
# it: build -> push to a registry -> scan the digest the registry returned.
#
#   bash scripts/scan-image.sh [out-dir]   (default: ./scan-out)
#
# The registry is a throwaway local container (distribution 3.1.2, pinned
# by digest) on 127.0.0.1 only, deleted at the end. Nothing leaves the
# machine. Scanning "k8s-lab/api:0.2.0" instead would scan whatever that tag
# points to at scan time - the scenario 6 problem, in CI.
#
# Gate: fail on HIGH or CRITICAL vulnerabilities that have a fix available
# (--ignore-unfixed). Unfixed ones are reported, not gated: nobody can act
# on them except by changing the base image. Exit code 3 means findings,
# so a trivy error (exit 1) is never confused with them.
# Also writes a CycloneDX SBOM of the same digest into out-dir.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${API_IMAGE:-k8s-lab/api:0.2.1}
REGISTRY_IMAGE=docker.io/library/registry:3.1.2@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c
PORT=${REGISTRY_PORT:-5055}
NAME=lab-scan-registry
out=${1:-scan-out}
mkdir -p "$out"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:5000" "$REGISTRY_IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/v2/" >/dev/null 2>&1 && break
  sleep 1
done

remote="127.0.0.1:$PORT/$IMAGE"
docker tag "$IMAGE" "$remote"
push=$(docker push "$remote")
digest=$(grep -oE 'digest: sha256:[a-f0-9]{64}' <<<"$push" | awk '{print $2}')
[ -n "$digest" ] || { echo "no digest in docker push output" >&2; exit 2; }
ref="127.0.0.1:$PORT/${IMAGE%:*}@$digest"
echo "==> scanning $ref"
echo "$ref" > "$out/scanned-ref.txt"

# --insecure: the throwaway registry speaks plain HTTP on loopback.
trivy image --quiet --insecure --format cyclonedx --output "$out/sbom.cdx.json" "$ref"
echo "    SBOM: $out/sbom.cdx.json"

trivy image --quiet --insecure --severity HIGH,CRITICAL "$ref" \
  | grep -E '^(Total|[^ ].*\(alpine|Node.js)' || true
rc=0
trivy image --quiet --insecure --exit-code 3 --ignore-unfixed \
  --severity HIGH,CRITICAL "$ref" > "$out/trivy-fixable.txt" || rc=$?
case $rc in
  0) echo "PASS  no fixable HIGH/CRITICAL vulnerabilities in $digest" ;;
  3) echo "FAIL  fixable HIGH/CRITICAL vulnerabilities in $digest:"
     cat "$out/trivy-fixable.txt"; exit 1 ;;
  *) echo "ERROR trivy failed (exit $rc)"; cat "$out/trivy-fixable.txt"; exit 2 ;;
esac

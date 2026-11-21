#!/usr/bin/env bash
# Renders a kustomize overlay with the locally built api image pinned by
# digest, on stdout:  bash scripts/render-pinned.sh k8s/overlays/hardened
#
# Why this exists (scenario 6): third-party images are pinned in the overlay
# itself (k8s/overlays/hardened/kustomization.yaml), but the api image is
# built on this machine, so its digest is only known after "make load". In
# a real pipeline CI would build, push, and write the digest into the
# deployment repo; here we read it from the kind nodes instead.
#
# Two kind-specific steps:
#  1. The digest is taken from containerd on every node, not from Docker:
#     that is what the kubelet will actually run. All nodes must agree - a
#     tag that points to different content on different nodes is exactly
#     the mutable-tag problem.
#  2. "kind load" registers the image under its tag only. A registry pull
#     would also record "name@sha256:..."; without that name the kubelet
#     cannot find a digest reference locally and tries Docker Hub
#     (ErrImagePull). So the digest name is added on each node.
set -euo pipefail

OVERLAY=${1:?usage: $0 <kustomize overlay dir>}
IMAGE=${API_IMAGE:-k8s-lab/api:0.2.0}
CLUSTER=${CLUSTER_NAME:-k8s-lab}
CONTEXT=${KUBE_CONTEXT:-kind-$CLUSTER}
REF="docker.io/$IMAGE"

digest=""
for node in $(kind get nodes --name "$CLUSTER"); do
  # ctr columns: REF TYPE DIGEST SIZE PLATFORMS LABELS
  d=$(docker exec "$node" ctr -n k8s.io images ls "name==$REF" | awk 'NR == 2 {print $3}')
  if [ -z "$d" ]; then
    echo "render-pinned: $IMAGE is not loaded on node $node (run make load)" >&2; exit 1
  fi
  if [ -n "$digest" ] && [ "$d" != "$digest" ]; then
    echo "render-pinned: nodes disagree on $IMAGE: $digest vs $d on $node" >&2; exit 1
  fi
  digest=$d
  # Drop digest names left by earlier builds: the kubelet reports a pod's
  # imageID from the image's first digest name, so stale ones would make
  # "running imageID" disagree with the pinned digest. Content still used
  # under another name is not deleted by removing a name.
  docker exec "$node" ctr -n k8s.io images ls -q \
    | grep -F "${REF%:*}@sha256:" | grep -vF "$digest" \
    | xargs -r docker exec "$node" ctr -n k8s.io images rm >/dev/null
  docker exec "$node" ctr -n k8s.io images tag --force "$REF" "${REF%:*}@$digest" >/dev/null
done
echo "render-pinned: $IMAGE -> $digest" >&2

rendered=$(kubectl --context "$CONTEXT" kustomize "$OVERLAY")
pinned=$(sed "s|image: $IMAGE\$|image: $IMAGE@$digest|" <<<"$rendered")
if ! grep -qF "image: $IMAGE@$digest" <<<"$pinned"; then
  echo "render-pinned: no 'image: $IMAGE' line found in $OVERLAY" >&2; exit 1
fi
printf '%s\n' "$pinned"

#!/usr/bin/env bash
# Scenario 6 demo: an image tag is a movable pointer. Someone who can publish
# under an existing name (a leaked registry token, a compromised CI job, a
# typo-squatted base image) changes what runs - without touching git, the
# manifest or the cluster API. Only a pod restart is needed.
#
# Simulated LOCALLY: the "attacker's" image is the genuine api plus one
# marker file, built here and copied into the kind nodes with "kind load".
# No registry, nothing pushed. The genuine image is restored at the end.
# Runs on the host (needs docker and kind), not inside a pod.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
CLUSTER=${CLUSTER_NAME:-k8s-lab}

echo "Scenario 6: mutable image tags  (overlay: $(overlay))"
for t in docker kind; do
  command -v "$t" >/dev/null || { echo "this demo needs '$t' on the host" >&2; exit 2; }
done
kubectl -n "$NS" rollout status deploy/api --timeout=60s >/dev/null

spec_image() { kubectl -n "$NS" get deploy api -o jsonpath='{.spec.template.spec.containers[0].image}'; }
# Newest api pod: right after a rollout the old one may still be terminating.
running_id() {
  kubectl -n "$NS" get pods -l app=api --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1:].status.containerStatuses[0].imageID}'
}
restart_api() {
  # 2>&1: vulnerable's PSA warn=restricted prints a warning on every update.
  kubectl -n "$NS" rollout restart deploy/api >/dev/null 2>&1
  kubectl -n "$NS" rollout status deploy/api --timeout=120s >/dev/null
}

ref=$(spec_image)
tag_ref=${ref%%@*}   # the name:tag part an attacker can re-point

step "What the api Deployment references"
info "image: $ref"
case $ref in
  *@sha256:*) info "-> pinned by digest: the content hash is part of the reference" ;;
  *)          info "-> a tag only: whatever '$tag_ref' points to when the pod starts" ;;
esac
info "running imageID: $(running_id)"

# Keep the genuine image under a backup tag: once the tag is re-pointed, the
# old image has no name left and Docker may drop it.
backup="${tag_ref%:*}:lab-s6-genuine"
docker tag "$tag_ref" "$backup"
restore() {
  docker tag "$backup" "$tag_ref"
  docker rmi "$backup" >/dev/null
  kind load docker-image "$tag_ref" --name "$CLUSTER" >/dev/null 2>&1
}
trap restore EXIT

step "The 'attacker' re-publishes '$tag_ref' with different content"
docker build -q -t "$tag_ref" - >/dev/null <<EOF2
FROM $tag_ref
USER 0
RUN echo "lab scenario 6: not part of the genuine image" > /app/TAMPERED
USER 1000:1000
LABEL lab.scenario="6-tampered"
EOF2
kind load docker-image "$tag_ref" --name "$CLUSTER" >/dev/null 2>&1
info "same name, new content: $tag_ref -> $(docker image inspect --format '{{.Id}}' "$tag_ref")"

step "No change in git or in the manifest - just a pod restart"
info "(in real life: a node drain, an eviction, a scale-up, a crash)"
restart_api
info "Deployment image: $(spec_image)   (unchanged)"
info "running imageID:  $(running_id)"
if kubectl -n "$NS" exec deploy/api -- cat /app/TAMPERED >/dev/null 2>&1; then
  info "/app/TAMPERED exists -> the pod now runs the attacker's image"
else
  info "/app/TAMPERED is absent -> the pod still runs the pinned, genuine image"
fi

step "Clean-up: restore the genuine image and restart api"
trap - EXIT
restore
restart_api
info "running imageID: $(running_id)"

cat <<'EOF2'

Impact (vulnerable): the same manifest runs different code after any
restart. Image scans, signatures checked at build time and code review all
apply to an image that is no longer the one running; with IfNotPresent two
nodes can even run different versions under one tag.
Hardened: images are referenced as name:tag@sha256:digest, so the runtime
starts exactly that content; re-pointing the tag changes nothing.

Next: make verify-6   (exit 0 = still exploitable)
EOF2

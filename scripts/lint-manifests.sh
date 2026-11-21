#!/usr/bin/env bash
# Renders every kustomization and validates the output with kubeconform
# against the Kubernetes 1.36 API schemas (strict: unknown fields fail too)
# and the Kyverno CRD schemas. No cluster needed.
#
#   bash scripts/lint-manifests.sh [out-dir]
#
# The rendered YAML stays in out-dir (default: a temp dir), so CI can feed
# the same files to "trivy config".
#
# Schemas are pinned to a commit, like everything else: "master" would make
# the same commit pass today and fail tomorrow.
#  - yannh/kubernetes-json-schema: the commit that added v1.36.4;
#  - datreeio/CRDs-catalog: policies.kyverno.io (ValidatingPolicy v1).
# The hardened overlay renders without the api digest (scripts/render-pinned.sh
# adds it at deploy time); that is fine for schema validation.
set -euo pipefail
cd "$(dirname "$0")/.."

K8S_VERSION=1.36.4
K8S_SCHEMAS=https://raw.githubusercontent.com/yannh/kubernetes-json-schema/5a69f8365c9d3ed7de997f5365e22481cf775fa2
CRD_SCHEMAS=https://raw.githubusercontent.com/datreeio/CRDs-catalog/784ec895547a36e548e6810b41f27baade3a0890

out=${1:-$(mktemp -d)}
mkdir -p "$out"

for k in k8s/base k8s/overlays/vulnerable k8s/overlays/hardened policies/kyverno; do
  name=$(tr / - <<<"$k")
  kubectl kustomize "$k" > "$out/$name.yaml"
  echo "rendered $k -> $out/$name.yaml ($(grep -c '^kind:' "$out/$name.yaml") objects)"
done

kubeconform -strict -summary -output text \
  -kubernetes-version "$K8S_VERSION" \
  -schema-location "$K8S_SCHEMAS/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json" \
  -schema-location "$CRD_SCHEMAS/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  "$out"/*.yaml

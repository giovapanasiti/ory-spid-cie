#!/usr/bin/env bash
# Lints and renders the Helm chart (default + staging values) and validates the
# rendered manifests against Kubernetes schemas. Does NOT contact any cluster.
#   helm:        local binary, else docker image alpine/helm (fallback)
#   validation:  kubeconform (local, else docker image), else kubectl --dry-run=client
set -euo pipefail
cd "$(dirname "$0")/.."

CHART=infrastructure/helm/iam-platform
HELM_IMAGE=alpine/helm:3.16.4
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.7
K8S_VERSION=${K8S_VERSION:-1.30.0}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }

if have helm; then
  helm_() { helm "$@"; }
elif have docker; then
  echo "helm not found: using docker image $HELM_IMAGE"
  helm_() { docker run --rm -v "$PWD":/w -w /w "$HELM_IMAGE" "$@"; }
else
  echo "ERROR: neither helm nor docker is available" >&2; exit 1
fi

echo "==> chart files in sync with config/kratos"
for f in identity.schema.json federated.jsonnet; do
  if ! cmp -s "config/kratos/$f" "$CHART/files/$f"; then
    echo "ERROR: $CHART/files/$f differs from config/kratos/$f (copy it over)" >&2; exit 1
  fi
done
echo "ok"

echo "==> secret hygiene: no inline secret values in the chart"
if grep -RInE '^[[:space:]]*(password|secret|token|cookie|cipher|system)[[:space:]]*:[[:space:]]*["'\'']?[A-Za-z0-9+/=_-]{16,}' "$CHART" --include='*.yaml' --include='*.yml'; then
  echo "ERROR: possible secret value committed in the chart" >&2; exit 1
fi
echo "ok"

declare -a SETS=("default::" "staging::-f $CHART/values-staging.yaml")
for set in "${SETS[@]}"; do
  name=${set%%::*}; args=${set#*::}
  echo "==> helm lint ($name)"
  # shellcheck disable=SC2086
  helm_ lint --strict "$CHART" $args
  echo "==> helm template ($name)"
  # shellcheck disable=SC2086
  helm_ template iam "$CHART" --namespace iam --kube-version "$K8S_VERSION" $args > "$OUT/$name.yaml"
  echo "rendered $(grep -c '^kind:' "$OUT/$name.yaml") resources"
done

echo "==> guard: admin ports never routed by an Ingress"
for name in default staging; do
  if awk '/^kind: Ingress/{i=1} /^---/{i=0} i' "$OUT/$name.yaml" | grep -E 'number: (4434|4445|8091)|name: .*-(kratos|hydra|federation-broker)-admin$'; then
    echo "ERROR: admin port/service exposed through Ingress ($name)" >&2; exit 1
  fi
  if grep -q 'app.kubernetes.io/component: fedsim' "$OUT/$name.yaml"; then
    echo "ERROR: test federation simulator rendered with $name values" >&2; exit 1
  fi
done
echo "ok"

echo "==> guard: testFederation without acknowledgement must fail"
if helm_ template iam "$CHART" --set testFederation.enabled=true >/dev/null 2>&1; then
  echo "ERROR: fedsim rendered without iUnderstandThisIsTestOnly" >&2; exit 1
fi
echo "ok"

validate() {
  local file=$1
  if have kubeconform; then
    kubeconform -strict -ignore-missing-schemas -summary -kubernetes-version "$K8S_VERSION" "$file"
  elif have docker; then
    docker run --rm -v "$OUT":/m:ro "$KUBECONFORM_IMAGE" -strict -ignore-missing-schemas -summary \
      -kubernetes-version "$K8S_VERSION" "/m/$(basename "$file")"
  elif have kubectl; then
    echo "kubeconform unavailable: falling back to kubectl client-side dry run (no schema validation)"
    kubectl apply --dry-run=client --validate=false -f "$file" >/dev/null
  else
    echo "WARNING: no validator (kubeconform/docker/kubectl) available: schema validation skipped" >&2
  fi
}
for name in default staging; do
  echo "==> schema validation ($name)"
  validate "$OUT/$name.yaml"
done
echo "==> all checks passed"

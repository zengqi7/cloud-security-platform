#!/usr/bin/env bash
set -euo pipefail
chart=deploy/helm/cloudguard
# Render-only test digest. Never publish/deploy this as an actual image.
args=(--set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set database.runtimeSecret=runtime --set database.migrationSecret=migration)
helm lint --strict "$chart" "${args[@]}"
helm template gate "$chart" "${args[@]}" > /tmp/cloudguard-rendered.yaml
helm template gate "$chart" "${args[@]}" --set migration.enabled=true --show-only templates/migration.yaml > /tmp/cloudguard-migration.yaml
helm template gate "$chart" "${args[@]}" --set ingress.enabled=true --set ingress.host=gate.example.com --set ingress.tlsSecret=tls > /tmp/cloudguard-ingress.yaml
if helm template gate "$chart" >/dev/null 2>&1; then
  echo 'chart accepted missing immutable image/secret configuration' >&2; exit 1
fi
if helm template gate "$chart" "${args[@]}" --set api.replicas=1 >/dev/null 2>&1; then
  echo 'chart accepted non-HA API replica count' >&2; exit 1
fi

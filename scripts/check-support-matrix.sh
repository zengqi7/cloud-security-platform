#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

[[ "$(tr -d '\r\n' < VERSION)" == "0.1.0" ]]
grep -Eq '^go 1\.27\.2$' go.mod
grep -Fq 'FROM golang:1.27.2-alpine' Dockerfile
grep -Fq 'image: mysql:8.4' compose.yaml
grep -Fq 'FROM aquasec/trivy:0.75.0 AS trivy' Dockerfile
grep -Fq 'FROM openpolicyagent/opa:1.21.1-static AS opa' Dockerfile
grep -Fq 'ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8' Dockerfile
grep -Fq '| Go | 1.27.x for source builds | 1.27.2 |' docs/support-matrix.md
grep -Fq '| MySQL | 8.4 LTS | 8.4.11,' docs/support-matrix.md
grep -Fq '| OPA | 1.21.x | 1.21.1 |' docs/support-matrix.md
grep -Fq '| Trivy | 0.75.x | 0.75.0 |' docs/support-matrix.md
grep -Fq '| Cosign | 3.1.x | 3.1.3,' docs/support-matrix.md

echo 'support matrix metadata is consistent'

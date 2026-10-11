#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="$(tr -d '\r\n' < VERSION)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
grep -Fq "release \`v$version\`" docs/support-matrix.md
grep -Eq '^go 1\.27\.2$' go.mod
grep -Fq 'FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build' Dockerfile
grep -Fq 'mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242' compose.yaml
grep -Fq 'FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy' Dockerfile
grep -Fq 'FROM openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e AS opa' Dockerfile
grep -Fq 'ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8' Dockerfile
grep -Fq '| Go | 1.27.x for source builds | 1.27.2 |' docs/support-matrix.md
grep -Fq '| MySQL | 8.4 LTS | 8.4.11,' docs/support-matrix.md
grep -Fq '| OPA | 1.21.x | 1.21.1 |' docs/support-matrix.md
grep -Fq '| Trivy | 0.75.x | 0.75.0 |' docs/support-matrix.md
grep -Fq '| Cosign | 3.1.x | 3.1.3,' docs/support-matrix.md

echo 'support matrix metadata is consistent'

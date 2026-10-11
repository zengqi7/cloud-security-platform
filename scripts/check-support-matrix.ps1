$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Assert-Contains([string]$Path, [string]$Value) {
    $content = Get-Content -LiteralPath (Join-Path $root $Path) -Raw -Encoding UTF8
    if (-not $content.Contains($Value)) {
        throw "$Path does not contain expected value: $Value"
    }
}

$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw -Encoding UTF8).Trim()
if ($version -ne '0.1.0') { throw "VERSION must be 0.1.0, got $version" }

Assert-Contains 'go.mod' "go 1.27.2"
Assert-Contains 'Dockerfile' 'FROM golang:1.27.2-alpine'
Assert-Contains 'compose.yaml' 'image: mysql:8.4'
Assert-Contains 'Dockerfile' 'FROM aquasec/trivy:0.75.0 AS trivy'
Assert-Contains 'Dockerfile' 'FROM openpolicyagent/opa:1.21.1-static AS opa'
Assert-Contains 'Dockerfile' 'ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8'
Assert-Contains 'docs/support-matrix.md' '| Go | 1.27.x for source builds | 1.27.2 |'
Assert-Contains 'docs/support-matrix.md' '| MySQL | 8.4 LTS | 8.4.11,'
Assert-Contains 'docs/support-matrix.md' '| OPA | 1.21.x | 1.21.1 |'
Assert-Contains 'docs/support-matrix.md' '| Trivy | 0.75.x | 0.75.0 |'
Assert-Contains 'docs/support-matrix.md' '| Cosign | 3.1.x | 3.1.3,'

Write-Output 'support matrix metadata is consistent'

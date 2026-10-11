$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Assert-Contains([string]$Path, [string]$Value) {
    $content = Get-Content -LiteralPath (Join-Path $root $Path) -Raw -Encoding UTF8
    if (-not $content.Contains($Value)) {
        throw "$Path does not contain expected value: $Value"
    }
}

$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw -Encoding UTF8).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "invalid VERSION: $version" }
Assert-Contains 'docs/support-matrix.md' ('release `v' + $version + '`')

Assert-Contains 'go.mod' "go 1.27.2"
Assert-Contains 'Dockerfile' 'FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build'
Assert-Contains 'compose.yaml' 'mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242'
Assert-Contains 'Dockerfile' 'FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy'
Assert-Contains 'Dockerfile' 'FROM openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e AS opa'
Assert-Contains 'Dockerfile' 'ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8'
Assert-Contains 'docs/support-matrix.md' '| Go | 1.27.x for source builds | 1.27.2 |'
Assert-Contains 'docs/support-matrix.md' '| MySQL | 8.4 LTS | 8.4.11,'
Assert-Contains 'docs/support-matrix.md' '| OPA | 1.21.x | 1.21.1 |'
Assert-Contains 'docs/support-matrix.md' '| Trivy | 0.75.x | 0.75.0 |'
Assert-Contains 'docs/support-matrix.md' '| Cosign | 3.1.x | 3.1.3,'

Write-Output 'support matrix metadata is consistent'

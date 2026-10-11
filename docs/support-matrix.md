# Support matrix

This matrix applies to release `v0.1.1`. "Supported" is the declared release
contract. "Verified" records the exact versions and environments exercised for
the v0.1.x line; it does not establish a minimum compatible Docker version.
Historical capacity inputs retain the original v0.1.0 candidate commit.
Exact patch download/runtime outcomes are recorded in the Release notes;
cross-compilation is not native validation.

## Runtime and toolchain

| Component | Supported range | Verified version | Verification |
|---|---|---|---|
| Go | 1.27.x for source builds | 1.27.2 | Windows amd64 native build/test; Linux amd64 GitHub Actions build, race test and vet |
| MySQL | 8.4 LTS | 8.4.11, `mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242` | Linux amd64 container integration and migration tests |
| Docker Engine | Current maintained release; no minimum claimed | 29.8.2 | Docker Desktop using the WSL2 Linux amd64 engine |
| Docker Compose | Compose v2 plugin; no minimum claimed | 5.5.1 | Full local stack and isolated smoke environment |
| OPA | 1.21.x | 1.21.1 | Bundled Linux amd64 binary; real Rego policy and integration tests |
| Trivy | 0.75.x | 0.75.0 | Bundled Linux amd64 binary; manifest and digest-pinned image scans |
| Cosign | 3.1.x | 3.1.3, image `sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8` | Bundled Linux amd64 binary; identity-policy verification path tested |

## Platforms

| Platform | Status for v0.1.x | Evidence |
|---|---|---|
| Linux amd64 | Native CI and container runtime verified | Ubuntu 24.04 GitHub-hosted runner; Docker Desktop WSL2 local smoke with OPA, Trivy and Cosign |
| Windows amd64 | Native Go source build/test and CLI verified | Windows host with Go 1.27.2; external scanner bundle remains Linux-container only |
| Linux arm64 | Cross-compile only | `CGO_ENABLED=0` release archive build; bundled scanner container not natively exercised |
| Windows arm64 | Cross-compile only | `CGO_ENABLED=0` release archive build; external scanner setup required |
| macOS amd64 | Cross-compile only | `CGO_ENABLED=0` release archive build; external scanner setup required |
| macOS arm64 | Cross-compile only | `CGO_ENABLED=0` release archive build; external scanner setup required |

Cross-compilation proves that the project binaries build for a target. It does
not claim native runtime verification. Release archives do not bundle OPA,
Trivy or Cosign; the container image does.

Run `bash scripts/check-support-matrix.sh` or
`./scripts/check-support-matrix.ps1` after changing a pinned version.

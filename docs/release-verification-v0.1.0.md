# v0.1.0 release verification

Verification date: 2026-10-11. The release was kept as a draft until every
gate in this document passed. Evidence describes this tagged release only;
later commits on `main` do not change the tag or the assets already verified.

## Release identity

| Field | Verified value |
|---|---|
| Tag | `v0.1.0` |
| Annotated tag object | `904103c86a48f30927cb7d19e846bc77eca336ce` |
| Source commit | `d0e27344889ecc793c5c9617da470f2ad23887b5` |
| Tag signature | GitHub `verified=true`, reason `valid` |
| Signing key | Ed25519 `SHA256:P1DZmNa98gkb+Dc5lTo3qET8AetjmUgKTORFni5F+zg` |
| Release workflow | [run 38145492746](https://github.com/zengqi7/cloud-security-platform/actions/runs/38145492746), successful |
| Tagged-source CI | [run 38143452349](https://github.com/zengqi7/cloud-security-platform/actions/runs/38143452349), successful |

`git verify-tag v0.1.0` verified the same key locally. The release workflow's
exact-tag/main preflight, unit and race tests, vet, vulnerability scan, real
integration tests, container build, packaging, checksums and build-attestation
jobs all passed.

GitHub reports `isImmutable=false` because immutable releases are not enabled
for this repository. Maintainers must therefore treat the signed tag and the
verified asset set as append-only and never replace or move them. Consumers
must still verify both checksums and attestations after every download.

## Download verification

All assets were downloaded into a new directory. The verifier required the
exact repository, source commit, tagged workflow identity
`zengqi7/cloud-security-platform/.github/workflows/release.yml@refs/tags/v0.1.0`,
workflow signer commit, source tag ref, GitHub-hosted runner and GitHub OIDC
issuer. It did not bypass TUF metadata, certificate, transparency-log or
identity checks. Six of six checksums and six of six GitHub build attestations
passed.

| Archive | SHA-256 |
|---|---|
| `cloud-security-platform-v0.1.0-darwin-amd64.tar.gz` | `3bf53ee22f2ade90219846d2ba48a9d4b65d04d4fe5ed8e3e70afb1f08231a74` |
| `cloud-security-platform-v0.1.0-darwin-arm64.tar.gz` | `15592ea3209f9d573f9e4d282e0df05447ffcf330e3da78326fc2321c64f26b9` |
| `cloud-security-platform-v0.1.0-linux-amd64.tar.gz` | `3f37cf1ef3c1c5ecadf90f02c950f5481c7292ea958610ba5176c0bb1efab67b` |
| `cloud-security-platform-v0.1.0-linux-arm64.tar.gz` | `3929aa5323df2cdbaa25951c78f33eede7ddaf7738217fb3e3a81474f5b435b0` |
| `cloud-security-platform-v0.1.0-windows-amd64.zip` | `4859dd43ea351a85f38088cf3d9a14428fc26690c84249020ec202fb7e14fe26` |
| `cloud-security-platform-v0.1.0-windows-arm64.zip` | `4c3e9046a89e240e4375a37c14be9de4d3f90c435709cce3695cd985a3dd122b` |

The command and failure policy are documented in
[release-and-operations.md](release-and-operations.md). The verifier summary
and per-asset attestation JSON are operator evidence and are intentionally not
committed as mutable absolute-path output.

## Clean-room runtime

The downloaded Windows and Linux amd64 archives were extracted separately.
Each run used a new isolated Docker network, fresh MySQL 8.4 tmpfs instance,
random loopback ports and a one-hour API key. The release's own `migrate`,
`key`, API, worker and `cloudguard` binaries ran the scenario. The key was
revoked and rejected before teardown.

| Archive runtime | Result | Verified behavior |
|---|---|---|
| Windows amd64 | Pass | fresh migrations and readiness; submission idempotency; real OPA policy evaluation; unsafe manifest blocked; hardened manifest passed; point-in-time assessments; CLI exits 2/0; SARIF 2.1.0; credential revocation |
| Linux amd64 | Pass | same checks, with all application binaries running from the downloaded Linux archive |

OPA 1.21.1 was supplied as an external verified dependency, as required by the
archive contract. The Linux static binary SHA-256 was
`668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031`;
the Windows amd64 binary was checked against its official release checksum
before use.

## Capacity and limits

The reproducible capacity matrix, P95 latency, queue recovery, cold/warm image
scan and resource measurements are in
[capacity/v0.1.0.md](capacity/v0.1.0.md). At the offered 3 requests/s,
completion throughput remained approximately 2.966-3.068 jobs/s across the
matrix, backlog/crash recovery passed three repetitions each, and the
digest-pinned Alpine image's median cold/warm scans were 56.406/9.419 seconds.
These measurements are regression evidence, not an SLA.

Clean-room downloaded-archive runtime covered the OPA manifest path. Trivy
image scanning and optional Cosign/provenance policy paths are covered by the
tagged release workflow, integration tests and capacity evidence, but were not
repeated in these two archive smoke runs. Release archives do not bundle OPA,
Trivy or Cosign; the container image does.

macOS, arm64 and Windows arm64 archives passed cross-compilation, checksums and
provenance only; no native runtime execution is claimed. The tests do not cover
multi-host workers, MySQL failover, registry throttling, external CI providers,
production identity infrastructure or long-duration soak behavior.

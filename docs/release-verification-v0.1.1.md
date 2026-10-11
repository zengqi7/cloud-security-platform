# v0.1.1 completed release verification

Verification date: 2026-10-11 UTC. This report records completed checks after
publication; the signed v0.1.1 tag contains the final verifier and protocol,
while this report is added in a separate documentation PR. It does not move
the tag or change release assets.

## Identity and publication

| Field | Verified value |
|---|---|
| Release | [v0.1.1](https://github.com/zengqi7/cloud-security-platform/releases/tag/v0.1.1), latest, non-Draft, non-Prerelease |
| Published | 2026-10-11T15:53:24Z |
| Source / workflow signer commit | `9508446585e910dbb8d24928db072df35eb7a20c` |
| Signed annotated tag object | `9b6f8266bd62f991684091347552b1cf75d9f7ee` |
| Tag signature | local verification passed; GitHub verified=true, reason valid |
| Main CI | [38151967062](https://github.com/zengqi7/cloud-security-platform/actions/runs/38151967062), success |
| Snapshot release preflight | [38151972001](https://github.com/zengqi7/cloud-security-platform/actions/runs/38151972001), success |
| Tagged release workflow | [38152334557](https://github.com/zengqi7/cloud-security-platform/actions/runs/38152334557), success |
| Platform immutability | `isImmutable=true`; `gh release verify v0.1.1` passed |
| Asset release attestation | `gh release verify-asset` passed for all eight assets, including checksums.txt |

Both runtime tests and seven strict build-provenance checks passed while the
release was a Draft. Publication then locked the tag and eight-asset set.
The older v0.1.0 release ID, seven asset IDs/digests and signed tag object were
compared with the captured baseline and are unchanged. Its historical
`isImmutable=false` is not retroactively changed by the new repository setting.

## Download and benchmark audit

GitHub CLI 2.102.0 downloaded exactly six binary archives, benchmark-evidence.tar.gz
and checksums.txt into an empty directory. All seven SHA-256 values and GitHub
build attestations passed with source and signer commit pinned to the value
above, source ref `refs/tags/v0.1.1`, tagged workflow identity
`zengqi7/cloud-security-platform/.github/workflows/release.yml@refs/tags/v0.1.1`
and self-hosted runners denied. No trust or identity checks were bypassed.
Release attestation checks after publication additionally covered all eight
downloaded files, including the checksum file itself.

| Archive | SHA-256 |
|---|---|
| benchmark-evidence.tar.gz | `34418847df4b701d9dcf006bbdae7caa1339fca726869f5d78a34b729398d80c` |
| darwin-amd64.tar.gz | `e8ff6693e93fd60088712f09ac9b817878963ff8dfd7c2db46aae7ab442ff9dd` |
| darwin-arm64.tar.gz | `9a7e8062e4bfb62b2daddde38bad489d56c8553d6752ceddf209de9621e6e3dd` |
| linux-amd64.tar.gz | `6bda23db3d04ff85e77e692b151d6bf3ab0bdda146d69ac237893528ce4b9072` |
| linux-arm64.tar.gz | `7e3dbaaf0fca7ba55c0adf201542020a33a0571bbc6e1f0463ed12b35f1fbfc5` |
| windows-amd64.zip | `739daa7bb1c238ee5eb2b7e1397ebed654196bde9f0368729b19679ce8826cbf` |
| windows-arm64.zip | `e998af9943c3d8995ac1a540117b1dfb9092222efa7be7e2e7b3004f22e9838b` |

Binary archive names have prefix `cloud-security-platform-v0.1.1-`.
The downloaded benchmark archive's internal hashes and derived resource/
latency/queue summaries passed `python capacity/evidence.py audit` after extraction.
The sanitized evidence retains 33 manifest runs plus three image comparisons,
at historical candidate `1d85296d26466083817523ef1cf74b3cc0cf97dd`.
This patch did not perform fresh v0.1.1 capacity measurement. HTTP admission
P95 is the preserved k6 aggregate; request-level HTTP samples were not retained.
Completion latencies and resource statistics can be independently recomputed.

## Downloaded-package runtime

| Platform | Result / completed UTC | Scope |
|---|---|---|
| Windows amd64 | Pass, 2026-10-11T15:47:50Z | native downloaded application binaries |
| Linux amd64 | Pass, 2026-10-11T15:48:29Z | downloaded Linux binaries in isolated containers |

Each run used a fresh MySQL 8.4 tmpfs database, new isolated Docker network,
random loopback ports and a one-hour API key. The downloaded migrate/key/API/
worker/cloudguard binaries verified readiness, submission idempotency, real
OPA 1.21.1 evaluation, unsafe block, safe pass, fresh assessments, CLI exits
2/0, SARIF 2.1.0 and rejection of the revoked credential. Temporary resources
were removed. Linux OPA was checksum-pinned; Windows OPA was checked against
its official release checksum. No application binary was compiled locally.

This runtime scope covers OPA Manifest scanning; Trivy/Cosign image and
supply-chain paths retain their earlier CI/capacity evidence. macOS and arm64
archives were cross-compiled but not natively exercised. External scanners
remain required. Short local tests are not a production SLA, and provenance
proves build origin rather than runtime safety or reproducible binaries.

Follow [the tagged verification protocol](https://github.com/zengqi7/cloud-security-platform/blob/v0.1.1/docs/release-verification.md),
[support matrix](support-matrix.md), [historical capacity report](capacity/v0.1.0.md)
and [auditable inputs](../capacity/evidence/v0.1.0). Operator JSON records and
logs remain local; sanitized benchmark evidence is public and checksummed.

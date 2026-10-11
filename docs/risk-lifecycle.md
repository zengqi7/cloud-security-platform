# Assets, comparable scans and SBOM

Supply `asset` (stable service identity, up to 255 bytes) and `series` (environment or pipeline, up to 128 bytes) on scan submission, or CLI `-asset checkout-api -series prod`. The Action has the same inputs. The tenant and scan kind also form the asset identity. Without explicit asset the target is the identity; different digests will therefore be separate assets. Series defaults to `default`.

Image release scans require `registry/repository@sha256:<64 lowercase hex>`; mutable tags are not release evidence. The worker records the actual Trivy version, confirms the requested digest in Trivy metadata, runs the OS/library vulnerability profile, and generates CycloneDX from the same digest. The entire result settles under the database lease and fencing token. Imported reports remain unverified and cannot authorize release.

`GET /api/v1/scans/{current}/diff?base={previous}` returns comparability and new, retained, resolved and possibly_fixed findings. Both scans must succeed with complete evidence, have the same tenant/asset/series, pinned policy, profile, scanner/version and coverage, and strictly increasing creation and completion times. Changed manifest workload/container coverage, UNKNOWN severity or missing evidence rejects comparison. A policy change requires a new baseline.

Finding matching uses rule/resource/package, independent of installed/fixed version. Resolved means absent within a comparable scan. Only an image artifact digest change also yields `possibly_fixed`; removal, package replacement or vulnerability database changes can cause absence, so this is not a verified fix. Trivy resource identifiers changing with OS target versions may yield new/resolved instead of retained; this conservative limitation is explicit.

`GET /api/v1/scans/{id}/sbom` requires `scans:read`. JSON is canonicalized before SHA-256 hashing and on retrieval, avoiding MySQL JSON formatting drift. Digest mismatch fails the request. This hash detects corrupted stored data relative to stored evidence; it is not an external attestation or a defense against a privileged operator rewriting both fields. Waivers never mutate findings, SBOM or risk deltas.

## Verification

Integration tests use real MySQL with clearly labelled synthetic scanner evidence to test tenant isolation, comparison rejection, missing evidence and SBOM tampering. The opt-in real scanner test is separate:

```powershell
$env:TRIVY_INTEGRATION_TARGET='alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
$env:SCAN_DATA_DIR='E:\cloud-security-platform\data'
go test -count=1 -v ./internal/platform -run TestRealTrivyEvidence
```

It checks real tool success, digest confirmation and CycloneDX evidence. Availability of that external digest/registry is required; routine CI does not fabricate equivalent supply-chain evidence.

# Supply chain evidence

Enable object storage and EVIDENCE_REQUIRE_ARCHIVE=true for production. New image
scans retain the original Trivy report, CycloneDX SBOM, Cosign verified signature
output and verified provenance envelopes when required by SLSA_BUILDER_ID. JSON
value streams from Cosign are archived as a JSON array. Each blob has SHA256,
size and tenant/scan/attempt index metadata; upload failures prevent settlement.
Retrieve authenticated artifacts at `/api/v1/scans/{id}/evidence/{kind}` with
scans:read (`report`, `sbom`, `signature`, `provenance`). Objects are not public
and API responses do not expose bucket keys or credentials. Reports may contain
private package/source information: apply tenant access and retention controls.

New trust snapshots are version 2 and bind verification to exact artifact digest,
Cosign version, policy digest and verification timestamp. Vulnerability DB evidence
expires after 48 hours; enabled signature verification also expires after
SUPPLY_CHAIN_MAX_AGE_SECONDS (default 86400; allowed 300..172800). Assessments
are capped by the earlier deadline. Missing/invalid/future evidence cannot pass.
Historical snapshots are unchanged and retain their original interpretation.

Key mode snapshots hash the exact public key. For planned rotation mount a public
COSIGN_KEYRING_DIR containing `<sha256>.pub` files for queued old-policy jobs, and
point COSIGN_PUBLIC_KEY at the new submission key. Verification hashes the selected
bytes before use. Keyless mode retains exact certificate identity and issuer.
On compromise, distribute TRUST_REVOKED_DIGESTS (comma-separated key or trust
snapshot hashes) to all API/worker replicas, or change TRUST_POLICY_EPOCH to
invalidate prior version-2 evaluations. Rotate/restart all replicas together before
reopening traffic to avoid mixed revocation views. Previously issued immutable
assessments remain historical records; consumers must check validity and revoke
or invalidate their own cached approvals during an incident.

SLSA verification accepts in-toto Statement/v1 with
`https://slsa.dev/provenance/v1`, the exact SHA256 subject and trusted builder ID.
The SLSA specification release and provenance predicate version are independent.
Verified provenance does not by itself establish a SLSA build level. Disabled
trust mode is visible in snapshots and never claims signature/provenance validity.

Live keyless transparency-log/TUF, public-key rotation, revoked signer and offline
failure scenarios still need trusted signed fixture images in staging. Unit tests
of bindings and expiry do not substitute for those external service tests.

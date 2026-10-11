# Supply-chain requirements and durable rescans

## Trust configuration

Image scans snapshot operator policy at submission; clients cannot disable it. Default `SUPPLY_CHAIN_MODE=disabled` adds no signature requirement and makes no authenticity claim. Enable one mode on API and workers:

- `key`: `COSIGN_PUBLIC_KEY` points to a local read-only public key. Its SHA-256 is pinned; workers reject a changed key and verify using a private temporary copy of those exact bytes.
- `keyless`: set exact `COSIGN_IDENTITY` and `COSIGN_ISSUER` (no broad regular expression). Cosign performs normal certificate, transparency log and image claim verification.

`COSIGN_BIN` overrides the verified operator-installed executable; the container bundles Cosign 3.1.3. Set `SLSA_BUILDER_ID` to additionally require verified SLSA v1 provenance. After Cosign `verify-attestation --type slsaprovenance1` succeeds, parse verified DSSE payloads and match in-toto Statement/v1, SLSA v1 predicate, SHA-256 subject and exact runDetails.builder.id. No JSON supplied by the scan caller is trusted. Failure, empty output, timeout or identity mismatch cannot pass. No insecure transparency-log bypass exists in the application.

Compose supports keyless mode directly through environment variables. Key mode additionally needs the same read-only public-key mount on API and worker and `COSIGN_PUBLIC_KEY` configured through an operator Compose override. Never mount signing private keys. Cache/work data should reside on the operator-selected data volume.

Evidence stores the pinned policy and SHA-256 hashes of successful Cosign outputs; it does not archive whole certificates/attestations for offline independent verification. Trusted builder identity alone is not a SLSA assurance level or a proof that source/dependencies are safe. Egress to registries and Sigstore services must be controlled by the deployment; network failure rejects evidence. Trust configuration is deployment-wide, not per-tenant. Rotation requires completing old pinned work with the old public key or creating new scans/schedules; current policy cannot rewrite history.

## Database freshness

Trivy updates its database first. Capture `db/metadata.json` UpdatedAt, then scan with `--skip-db-update` and confirm it did not change during the operation. DownloadedAt does not measure content freshness. Missing/invalid metadata, a clock more than five minutes in the future or age of at least 48 hours rejects approval. A fresh assessment is bounded by DB UpdatedAt + 48 hours, waiver expiry and the 15-minute assessment window. Historical assessment JSON stays immutable. Waivers cannot override stale or untrusted evidence. Manifest scans do not use a vulnerability DB.

This is freshness of Trivy's vulnerability database, not proof of complete vulnerability knowledge. Java package-identification data and remote feeds are dependencies of Trivy; no independent feed freshness or completeness guarantee is claimed. Shared-cache changes cause conservative retry. Use controlled scanner cache volumes and synchronized clocks.

## Durable rescan scenario

After scanning a fixed deployment image, create:

```http
POST /api/v1/rescans
Authorization: Bearer <scans:submit + rescans:write credential>
Content-Type: application/json

{"scan_id":"<successful scan id>","interval_seconds":86400}
```

The schedule keeps the request, stable asset/series, policy digest, operator trust snapshot, creator/key and next due time in MySQL. Workers lock a due schedule using SKIP LOCKED, recheck the credential's subject/scopes/expiry/revocation, create a new job with a unique schedule/period idempotency key, advance its deadline and write audit in one transaction. A crash rolls back both. Outage periods coalesce to one scan, then the next period is measured from database dispatch time. Revoked/expired credentials disable the schedule. `GET /api/v1/rescans/{id}` reads it; `POST .../{id}/disable` accepts `{"reason":"retired deployment"}`.

This rescans the same immutable artifact to discover new CVEs; it does not follow mutable tags, discover running clusters or automatically approve/deploy anything. Each create call creates a schedule, so callers must persist the returned ID and avoid retrying ambiguous creates blindly. Long scans can overlap when interval/queue latency warrants it; there is no per-asset mutex or deadline SLA. Disabled schedules require creating a replacement to renew credentials/trust. Scans and audit history have no automatic retention cleanup yet.

## Verification

Real MySQL tests cover eight competing schedulers, durable coalescing, exactly one new job per committed period, tenant isolation and credential revocation. Unit tests cover time boundaries and provenance digest/builder rejection. Opt-in `TestRealCosignVerification` requires an explicit digest and operator identity/key; `COSIGN_EXPECT_REJECT=true` tests fail-closed against an untrusted artifact. No fixture result counts as successful external signature verification.

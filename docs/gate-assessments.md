# Point-in-time gates and TTL waivers

Original findings and scan summaries never change when a waiver is approved.
`POST /api/v1/scans/{id}/assessments` creates an immutable decision from the
finished scan's pinned policy, original counts, approved matching waivers and
database evaluation time. Requires `assessments:write` and `Idempotency-Key`.
Same key/scan returns the original snapshot, even if it has expired; another
scan with the same key conflicts. Use a new key for a new evaluation.

`GET /api/v1/assessments/{id}` returns the historical snapshot with `scans:read`.
It contains original/effective gates, policy digest, evidence source, subject,
full applied approval data and `valid_until`. This is evidence, not a perpetual
release token. Its maximum validity is 15 minutes, reduced to the earliest
applied waiver expiry. Consumers must check the deadline; a later revocation
requires a new assessment before release. An expired record is never rewritten.

## Waiver workflow

1. `POST /api/v1/waivers` with `scan_id`, exact `fingerprint`, `reason`, and
   RFC3339 `expires_at` requires `waivers:request`. Expiry must be future and
   at most 30 days. Only completed, known-severity findings can be requested.
2. A different subject posts `action: approve` and `reason` to
   `/api/v1/waivers/{id}/decision` with `waivers:approve`. The requester cannot
   self-approve even with both scopes. Pending requests can be rejected; an
   approved, unexpired request can be revoked through the same endpoint.
3. A CI subject uses CLI `-assess` (Action `assess: 'true'`) with
   `assessments:write` and `scans:read`. Every CLI call creates a fresh assessment
   request key and rejects missing/expired response validity. Without `-assess`,
   the original gate applies and approved exceptions have no effect.

Waivers apply to one immutable scan and fingerprint, never all future versions
of an asset. Duplicate approvals for one fingerprint are counted once. UNKNOWN,
scanner failure, missing policy and unverified imports cannot be waived into
approval. Database tenant governance locks serialize decisions and evaluations;
audit writes commit with state changes. Failed audit/storage means no approval.
Identities must represent distinct people; issuing two subject names to one
person bypasses organizational separation and is an operator responsibility.

SARIF continues to describe original findings/gate. Retain the assessment JSON
alongside it to explain a waived release. API read scopes can view same-tenant
approval reasons. There is no UI, reusable cross-scan exception, external identity
provider or signed release attestation in this stage.

Reproduce with MySQL: `go run ./cmd/migrate`, then
`go test -tags=integration ./integration -run Assessment`. Tests cover self
approval, eight simultaneous idempotent assessments, original evidence,
database immutability, CLI waiver gate, expiry, tenant isolation and untrusted
imports without deleting demonstration data.

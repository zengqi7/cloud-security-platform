# Scan and release contract

## State machines and invariants

- Scan: queued -> running -> succeeded, or queued (retry), or failed after the attempt limit. Attempts increment at claim, including process crashes. Expired terminal attempts must commit even when no new scan is available.
- Tenant is obtained from the Bearer credential; another tenant sees 404 for a foreign ID. Unique (tenant, idempotency_key) binds to a request hash; changed content returns 409.
- Only a successful scan with valid current evidence can approve release. Pending, failed, undefined policy, unknown severity and expired evidence must fail closed as governance stages are enabled.
- Uploaded reports are input supplied by a caller, not proof of a scan or trusted release approval. C2 must restrict ingestion; provenance cannot be inferred from JSON validity.
- Original findings are immutable evidence. Waivers affect a separate point-in-time assessment, never the recorded scanner result.

## Migration and compatibility

Separate checksum-verified, locked migrations manage scan_jobs and normalized findings; service startup never executes DDL. Legacy JSON findings backfill before removal. Dirty or unknown newer migrations block startup. MySQL DDL is nontransactional: restore a backup to test upgrades, reconcile partial DDL explicitly, and never blindly replay a changed migration. Schema expansion precedes code upgrade; destructive contraction is a later release.

OpenAPI 3.1 is stored in docs/openapi.json. Responses may gain additive fields within v1. Auth/scanner trust changes require documented upgrade steps. Scan series may only compare successful complete evidence with the same asset and comparable scope; absence from a failed scan is not a fix.

## Validation

Run go test ./..., go vet ./..., real OPA policy tests, and integration-tag MySQL tests on a disposable schema. CI uses Linux race and builds the scanner container. Fixtures and demo reports must never be represented as production scan evidence.

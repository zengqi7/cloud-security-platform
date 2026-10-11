# Architecture and Decisions

## Components

- API: authenticates tenant tokens, validates bounded input, persists idempotent scan jobs, and serves summaries/findings.
- Worker: claims one job at a time, executes a scanner under a 150-second deadline, and persists success or retry state.
- MySQL: durable queue and result store.
- Trivy: remote container image vulnerability scanning.
- OPA: deterministic Kubernetes workload policy evaluation.

## Queue semantics

`scan_jobs` stores the request, result, attempt count, lease token and lease deadline. A claim uses `FOR UPDATE SKIP LOCKED`, increments attempts and creates a 180-second lease. Completion updates only a row whose status and lease token still match, which fences stale workers.

Scanner failures are retried after 15 seconds up to three attempts. A worker crash leaves a running row; after lease expiry it becomes claimable. After the final expired lease, the row is marked failed. Failed scans produce gate `error`, never `pass`.

## Result normalization

Trivy vulnerabilities and OPA violations become a common Finding model. A SHA-256-derived fingerprint over rule, resource, package and versions removes exact duplicates. Severity outside the supported set becomes `UNKNOWN`.

Scans pin immutable policy bundle/version/digest and deployment-wide trust configuration. UNKNOWN, incomplete, expired or unverified evidence fails closed. Original findings remain immutable; a separate assessment applies matching, approved TTL waivers from a different approver subject. Database time bounds validity by 15 minutes, waiver expiry and image vulnerability DB freshness. Historical assessments are never rewritten.

## Trust model

Database API keys carry tenant, subject, expiry and scopes; revoked/expired keys are rejected on each request. Imported Trivy reports require reports:import and are explicitly unverified input, not cryptographic attestations. A clean imported report cannot pass the release gate. See authentication.md for lifecycle and audit semantics.

Image release scans require @sha256 identity. Trivy updates its DB, records UpdatedAt, scans with skip-db-update, confirms stable metadata, and emits digest-checked CycloneDX SBOM. Optional Cosign verifies operator-pinned key/exact certificate identity and SLSA subject/builder before evidence can be trusted; disabled mode does not assert authenticity.

Assets and scan series define comparison scope. Only successful complete evidence with comparable scanner/policy/profile/coverage is comparable. Changed image digest yields possibly_fixed, not resolved. Durable rescan schedules retain request/policy/trust snapshots; worker transactions recheck creator credentials, enqueue once per due period and advance the schedule. Missed intervals coalesce.

MySQL stores normalized scan_findings, cached counts, policy bundles, governance locks, audit, immutable assessments and schedules. Go database/sql is the implementation boundary; this remains a single application. Explicit checksum/dirty/newer-schema migrations precede startup. CLI/Action fail closed and SARIF exports every findings page. See the stage-specific docs and release-and-operations.md for limitations and recovery.

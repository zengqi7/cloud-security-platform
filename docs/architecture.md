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

V1 gate policy blocks any HIGH or CRITICAL finding. This policy is intentionally simple and visible; per-tenant exceptions and expiry-controlled waivers are future scope.

## Trust model

Bearer tokens map to tenants at process startup. Imported Trivy reports are trusted input from authenticated automation, not cryptographic attestations. For supply-chain enforcement, add signed provenance verification before enabling imported reports outside a trusted network.

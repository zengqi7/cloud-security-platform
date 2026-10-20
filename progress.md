# CloudGuard Upgrade Progress

## 2026-10-20

- Confirmed implementation repository at `E:/cloud-security-platform`.
- Confirmed baseline from development records: v0.1.1, P0/C1-C7/O1 complete.
- Created production upgrade planning files; no source code changed.
- Next implementation entry point: P0 baseline/contract freeze, followed by P1 deployment foundation.

- P0 branch pushed; PR #33 CI test/static/container checks all passed.
- P1: added worker progress/readiness endpoints and bounded claim/scheduler calls;
  Helm HA deployments, migration Job, network policy and operating runbook in progress.
- Docker Desktop remains unavailable: engine.sock reparse point returns Windows
  error 1920; moving socket and moving its parent both failed without changes.
  No data/volumes were removed. Use CI for container validation while local
  disposable cluster tests remain pending; no further intrusive host repair.
- P1 local validation passed: platform/worker Go tests and vet; verified Helm
  v3.19.0 archive SHA256; strict chart lint and migration/TLS render variants.
  P0 PR #33 merged after all CI checks passed.
- P1 PR #34 all CI checks passed. P2 implements shared MySQL TLS/pool config,
  S3 SDK v2 integrity-checked dual writes, fenced linking and quarantined GC.
- P2 PR #35 opened. P3 implements RFC 9068 access-token OIDC, server-side
  expiring identity memberships, tenant/host registry credential references,
  per-job credential files and scanner child environment isolation.
- GitHub status request once returned EOF; safe read will be retried later.
- CI found the new evidence FK did not match scan_jobs.id ASCII/binary charset.
  Corrected the unapplied P2 migration before merge; tenant index also uses
  binary collation to preserve existing case-sensitive isolation. Existing
  released migrations remain untouched. Re-run uses a fresh CI database.

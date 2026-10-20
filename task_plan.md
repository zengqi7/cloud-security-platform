# CloudGuard Production Control Plane Upgrade

## Goal

Evolve the v0.1.1 CI/CD scan gate into a production cloud-native security control plane built around supply-chain evidence, Kubernetes policy/admission control, runtime telemetry feedback, and risk governance.

## Baseline

- Baseline: `main`/v0.1.1 work recorded as code tree `82ad0cbdcca75a33ded45b3033e443c9823473b3`.
- Completed: P0, C1-C7, O1; MySQL migrations, Trivy/OPA/Cosign/SBOM, assessments/waivers, rescans, CLI/SARIF/Action, release verification.
- Not yet production-proven: Kubernetes deployment, HA/RPO/RTO, private registry integration, Admission, runtime telemetry, SSO/RBAC UI, retention, enterprise CI interoperability.

## Phase Order

### Active v0.2.0 implementation (supersedes broad roadmap numbering below)

| Phase | Branch | Status |
|---|---|---|
| P0 contracts/regression | codex/v0.2.0-p0-contracts | PR #33 merged, CI passed |
| P1 Helm/HA | codex/v0.2.0-p1-kubernetes | local tests/lint passed, submitting PR |
| P2 MySQL/object storage | codex/v0.2.0-p2-storage | pending |
| P3 OIDC/registry credentials | codex/v0.2.0-p3-identity | pending |
| P4 evidence | codex/v0.2.0-p4-evidence | pending |
| P5 observability | codex/v0.2.0-p5-observability | pending |
| P6 recovery/capacity | codex/v0.2.0-p6-validation | pending |

Branches stack on their predecessor and PRs merge in dependency order. No
production release or SLA is claimed without real staging/recovery/soak evidence.
Untracked results/ is preserved and excluded from commits. Docker Desktop was
stopped at resumption; startup requested. Helm missing; install verified binary.
Previous Git schannel push failed; subsequent read and push succeeded without
disabling TLS verification.

1. P0-Baseline and contract freeze
2. P1-Production foundation and Kubernetes deployment
3. P2-Supply-chain evidence hardening
4. P3-Kubernetes inventory and policy control
5. P4-Admission control
6. P5-Runtime telemetry feedback
7. P6-Risk governance and remediation
8. P7-Enterprise identity, multi-cluster and platform operations
9. P8-Production validation and staged release

## Dependency Rules

- P0 must precede all implementation phases.
- P1 must precede Admission and runtime deployment.
- P2 must precede Admission decisions that depend on signatures/provenance.
- P3 must precede Admission policy evaluation against live cluster context.
- P4 must precede enforcement in production; start audit-only.
- P5 depends on stable asset identity from P3 and risk model from P6 may consume telemetry later.
- P6 must not change existing fail-closed scan semantics; assessments remain immutable.
- P7 must not be required for the single-tenant CI gate milestone.
- P8 is a release gate, not a feature phase; no production claim before it passes.

## Success Milestones

- M1: Existing v0.1.1 behavior remains green after schema/API compatibility tests.
- M2: HA Kubernetes deployment with backup/restore and observable SLOs passes staging drills.
- M3: Digest, SBOM, signature and provenance evidence is verifiable and admission-cacheable.
- M4: Cluster inventory and audit-only Admission work on a disposable Kubernetes cluster.
- M5: Runtime events correlate to assets and generate risk findings without blocking on telemetry loss.
- M6: Risk lifecycle, ownership, SLA, waiver and remediation workflows are auditable.
- M7: Production readiness review passes security, reliability, capacity and recovery criteria.

## Conflict Checks

- Do not replace MySQL queue with Kafka/Redis before measuring queue bottlenecks; add an event bus only for telemetry fan-in.
- Do not run full Trivy inside Admission; Admission reads fresh trusted evidence/cache.
- Do not make runtime telemetry a prerequisite for CI pass; missing telemetry is a visibility error, not proof of safety.
- Do not mutate historical findings or assessments while adding risk lifecycle tables.
- Do not call `possibly_fixed` a confirmed remediation when asset digest changed.
- Do not claim SLSA level or provenance authenticity when trust mode is disabled.

## Errors / Open Risks

| Item | Status | Handling |
|---|---|---|
| No local project plan existed | resolved | Created this plan and companion records |
| Current repository path differs from workspace root | resolved | Use `E:/cloud-security-platform` as implementation root |
| v0.1.1 capacity evidence is historical and single-host | open | Run new staging capacity/soak tests in P8 |
| SLSA site now identifies 1.2 as current | open | Define verifier compatibility policy in P2 before implementation |

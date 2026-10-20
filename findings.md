# CloudGuard Upgrade Findings

## Baseline Findings

- Current product is a CI/CD release-gate service, not an image registry or cluster runtime platform.
- Strong existing controls: durable MySQL queue, lease/fencing, tenant API keys, immutable policy bundles, fail-closed assessments, digest-bound Trivy evidence, CycloneDX SBOM, optional Cosign/SLSA checks, SARIF/Action and durable rescans.
- Existing evidence does not establish production SLA, multi-host HA, MySQL failover, registry throttling behavior, long soak stability, or native arm64 runtime.

## Directional Findings

- 2026 Red Hat research emphasizes platform consolidation, DevSecOps automation, supply-chain integrity, runtime protection, observability feedback, and AI governance.
- Kubernetes guidance requires lifecycle coverage across develop, distribute, deploy and runtime, including identity, isolation, network, storage, backup and observability.
- CNCF 2026 reports indicate Kubernetes is production infrastructure for AI and cloud-native workloads; hybrid cloud, multicluster, observability and immutable infrastructure are maturity signals.

## Recommended Technical Boundaries

- Keep the existing Go control plane and MySQL durable queue for scan jobs.
- Add Kubernetes Operator/Connector, Admission Webhook, and telemetry ingestion as separate adapters.
- Use mature runtime sensors (Falco/Tetragon/Cilium) instead of implementing eBPF detection from scratch.
- Use object storage for large SBOM/raw evidence; keep indexed metadata and digests in MySQL.
- Use an event bus only for high-volume telemetry fan-in; do not rewrite the scan queue prematurely.
- Use OPA/Rego or Kyverno/Gatekeeper-compatible policy packages for admission; preserve immutable policy digest semantics.

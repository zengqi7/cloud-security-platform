# Reproducible capacity harness

## Public benchmark evidence

The checked-in `capacity/evidence/v0.1.0/` contains allowlisted calculation
inputs from the historical measurements, `summary.json`, `resources.json`,
`metadata.json` and SHA-256 checksums. It is a sanitized audit snapshot, not a
claim that a new patch release was capacity-tested. Source commits come from
the original report because the original harness did not record HEAD.

`evidence.json` retains per-run admission counts/duration/P95, all completion
latencies, queue samples and numeric resource series; raw-input hashes identify
the private originals. Tokens, DSNs, env files, logs, local paths, ports, scan IDs
and container identities are excluded. The historical k6 export only retained
HTTP P95, so HTTP P95 itself cannot be independently recalculated from request
samples; completion P95 and resource medians can be.

```powershell
python capacity/evidence.py audit capacity/evidence/v0.1.0
python capacity/evidence.py pack capacity/evidence/v0.1.0 results/benchmark-evidence.tar.gz
```

CI audits the snapshot and uploads the deterministic archive plus its checksum
as a `benchmark-evidence` Actions artifact (90 days). Release packaging includes
the same evidence with the release checksum manifest and build provenance for
long-term discovery. Publication of v0.1.1 does not alter v0.1.0 assets.

The harness uses the KALM and k6 versions pinned in `lock.json`. Preparation
splits YAML documents and `List` objects, then includes only workload kinds that
the platform validates. Every source document and exclusion reason is retained
in `selection-audit.json`. Measurement is offline after images are present.

```powershell
E:\Anaconda\python.exe capacity\prepare_corpus.py E:\capacity-sources\kalm-6da1b2d.tar.gz
./capacity/run.ps1 -WorkerReplicas 2 -BatchSize 50 -Rate 2 -Duration 30s -Repetitions 3
```

The formal manifest matrix uses batches of 10, 50 and 100 resources with 1, 2
and 4 worker replicas. Digest-pinned image cold-cache and warm-cache scans are
reported separately because they are not comparable to OPA manifest throughput.
Backlog recovery and killed in-flight recovery (180-second lease) are distinct
scenarios. Each run uses an isolated Compose project, fresh volumes, fixed CPU
and memory limits, and one-second resource samples.

These are workload-specific single-host measurements, not an SLA or production
sizing promise.

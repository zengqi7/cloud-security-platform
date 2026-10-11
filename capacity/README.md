# Reproducible capacity harness

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

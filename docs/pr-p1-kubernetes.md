Add a digest-pinned Helm deployment for three API replicas and two independently
cached scan workers, with probes, disruption budgets, node spreading, explicit
network policy and existing Secret references. Add a worker health listener and
bounded queue/scheduler operations; transient DB loss affects readiness without
causing liveness restarts. Containers use numeric non-root UID/GID.

Migration is an explicit standalone Job, with a documented pause/backup/migrate/
restart sequence because current schema checks reject older binaries. No zero
downtime schema upgrade guarantee is introduced.

Validation: platform tests and vet; Helm strict lint and rendering including
migration/TLS variants and invalid settings. CI repeats these and the existing
race/MySQL/container checks. Local Kubernetes drills are pending: Docker Desktop
cannot start due to an inaccessible host secrets-engine socket; no Docker data
or volumes have been removed.

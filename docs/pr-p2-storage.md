Use a shared verified MySQL TLS/pool configuration for migration and runtime,
with bounded connection budgets and optional private CA. Add optional S3 SDK v2
SBOM dual writes and tenant-scoped integrity-checked reads. Reserve attempt keys
before upload, link only within lease-fenced SQL settlement, and collect only
unlinked objects older than 24 hours. Preserve SQL-only historical reads.

Tests cover TLS rejection, pool bounds, encrypted S3 protocol/integrity and real
MySQL settlement/tenant isolation/GC. Cloud failover and provider-specific S3/KMS
checks remain staging release gates.

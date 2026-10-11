# Versioned storage and finding queries

Stop API/worker, back up MySQL, test the migration against a restored copy, run `MYSQL_DSN=... go run ./cmd/migrate`, then start the new binaries. Compose adds a one-shot migrate service. API/worker startup verifies embedded migration checksums and never executes DDL. Do not resume old workers after the data contract changes.

Migrations hold a MySQL named lock on a dedicated connection. Each migration is marked dirty before its statements execute. MySQL DDL cannot roll back as a group: a failure leaves dirty metadata and blocks startup/retry. Inspect the failed statement and compare to a restored backup; reconcile deliberately, or restore and rerun. Never edit applied SQL, clear dirty blindly or run automatic destructive down scripts.

000001 adopts the known legacy scan_jobs table through CREATE IF NOT EXISTS. 000002 expands schema, copies all legacy array entries with JSON_TABLE into scan_findings and computes cached counts. Legacy findings_json remains as upgrade evidence; new workers write normalized findings and cached summary in the fenced settlement transaction. A failed/retried scan never inserts partial findings. Unknown severity fails closed.

The API reads scan metadata and cached counts without loading a full finding array. Finding pages use SQL COUNT, severity index and LIMIT/OFFSET, always joined to the credential tenant. Individual records retain their JSON metadata alongside indexed fingerprint/severity; this is not a second full-results JSON store. Tenant/time/id indexes support scan lists. Retention is operator-managed for this release: archive scan evidence before deletion, and do not delete referenced evidence once governance is enabled.

Repository, scanner, migration and HTTP interfaces remain explicit boundaries within the single Go application; no service split is added. Tests include legacy backfill, dirty/checksum rejection, expired terminal claims, stale settlement and tenant-filtered pagination. Use a disposable schema for these scenarios.

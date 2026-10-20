# Kubernetes deployment

Build the Dockerfile from the reviewed commit, publish to your registry and set
`image.repository` and `image.digest=sha256:...`. The chart deliberately has no
floating image default and does not install a database, secret manager or CNI.
Use Kubernetes 1.29+ with a NetworkPolicy-capable CNI. Provision at least two
worker nodes in separate failure domains, plus external highly available MySQL.
Node spreading does not replace multi-zone placement or database HA.

Create existing Secrets through your secret manager: runtime and migration
Secrets each have a `MYSQL_DSN` key. Runtime uses least privilege DML; migration
uses reviewed DDL/trigger privileges, never the production root account. Values
contain only Secret names. Do not pass passwords on shell command lines.

1. Back up database and test restore. Pause submissions, drain workers and scale
   old API/worker Deployments to zero before changing the schema. Current
   migration verification rejects schemas newer than the binary; **zero downtime
   mixed-version upgrades are not supported yet**.
2. Render the migration Job separately:
   `helm template gate deploy/helm/cloudguard -f staging.yaml --set migration.enabled=true --set migration.id=CHANGE_ID --show-only templates/migration.yaml`
   Review/apply that manifest and wait for Job completion before continuing.
   Investigate any failed DDL; do not bypass checksum verification or retry a
   partially applied migration blindly.
3. `helm upgrade --install gate deploy/helm/cloudguard -f staging.yaml --wait --timeout 10m`
   Keep `migration.enabled=false` in staging.yaml. Check endpoints and authenticated
   scan submission/polling across all replicas before resuming traffic.
4. Rollback needs a compatible binary or a restored database. `helm rollback`
   alone cannot roll back a schema. Record backup ID, image digest and schema.

Populate explicit NetworkPolicy ingress and egress rules. Default egress is
deny-all: allow namespace DNS UDP/TCP 53, database 3306, registries/Trivy DB/
Sigstore/OIDC/object-store HTTPS endpoints and telemetry collector ports as used.
Core NetworkPolicy has no FQDN rules: use a controlled egress proxy or a CNI with
FQDN policy for external SaaS; do not assume vendor IPs are static. Permit API
traffic only from the ingress controller/CI clients and metrics scrapes only
from monitoring. Public Ingress exposes `/api/` only and requires TLS.

API defaults to three replicas; workers to two, each processes one job at a time.
Queue claiming uses MySQL SKIP LOCKED and lease-token settlement fencing. SIGTERM
cancels active tools; workers have a separate 10-second bounded settlement window.
An interrupted job retries; a worker crash is recovered after the 180-second
lease expires. No process-local queue state is required for recovery. PDB covers
voluntary disruptions, not node loss. Do not scale below two replicas in HA.

Each worker uses its own ephemeral Trivy cache and writable /data and /tmp.
No shared RWX filesystem is required. Size ephemeral disk and requests for image
size and cold DB downloads; expect cold-start latency after rescheduling.
Root filesystem is read-only; numeric UID/GID and dropped capabilities are set.
Readiness checks DB connectivity; liveness checks loop progress without restarting
healthy processes on a transient DB outage. Startup allows 150 seconds for DB
and schema checks. Image pulls and all cloud endpoints need network reachability.

Validation: Helm lint/template is necessary but not cluster evidence. Record a
real install, node drain, worker kill/lease recovery and API replica loss on a
disposable cluster before declaring deployment HA verified.

# Managed storage

Set MYSQL_REQUIRE_TLS=true and tls=true in MYSQL_DSN; a mounted private CA PEM
may be supplied with MYSQL_TLS_CA_FILE for cloud/private certificates. Hostname
verification remains enabled. The same configuration is used by migrate and
runtime binaries. DSN errors are sanitized. Default dial/read/write timeouts are
5s/30s/30s. Pool defaults per process: 12 open, 4 idle, 5 minute lifetime, 1 minute
idle timeout; DB_MAX_OPEN_CONNS, DB_MAX_IDLE_CONNS and DB_CONN_MAX_LIFETIME override
these with validated bounds. Budget replicas * max open + migration/admin reserve
below managed MySQL max_connections. Failover still needs a real provider drill.

Enable S3 with OBJECT_STORE_BUCKET, OBJECT_STORE_REGION and optional HTTPS
OBJECT_STORE_ENDPOINT for compatible providers. OBJECT_STORE_PREFIX must end in
`/` if a directory prefix is desired. The AWS SDK default credential chain supports
workload identity or mounted external credentials; no cloud secrets in Helm values.
For IRSA/projected tokens explicitly mount the token and set AWS_WEB_IDENTITY_TOKEN_FILE
and AWS_ROLE_ARN (default service-account token mounting is disabled). Permit only
PutObject/GetObject/DeleteObject on the evidence prefix; grant KMS permissions if
OBJECT_STORE_SSE_KMS_KEY_ID is set. Writes always request SSE-S3 or SSE-KMS.

New SBOMs are dual-written to SQL and object storage. The SQL index links only
after fenced job settlement succeeds. Reads prefer indexed objects, verify size
and SHA256, and fall back to SQL only for historical scans with no object index.
An indexed missing/corrupt object is an error and cannot silently approve release.
Archive failure prevents successful settlement; lease recovery retries the job.
Workers reserve per-attempt object keys before upload; unlinked attempts are GC
candidates after 24 hours and only when their lease is no longer active. Run
`evidence-gc` as a restricted maintenance Job (100 objects/run). Linked objects
are never automatically deleted. Versioned bucket delete markers may leave
non-current versions: configure retention in accordance with backup policy.

Enable bucket versioning, encryption and access audit; choose retention/Object
Lock under your policy. Avoid bucket lifecycle rules that expire linked evidence.
This phase keeps historical SQL evidence and does not reclaim old rows. Test
backup of SQL and object versions as a single recovery boundary before rollout.
No managed cloud resources are provisioned by the chart.

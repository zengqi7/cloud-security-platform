# Immutable policy bundles

`POST /api/v1/policies` requires `policies:publish`. Body:
`version`, `rego`, `block_severities`, `tests` (each with Kubernetes JSON
`manifest` and `expected_gate`, either pass or block). HIGH and CRITICAL remain
mandatory blocking severities; MEDIUM/LOW can be added. UNKNOWN always errors.
At least one passing and one blocking test must execute successfully with OPA.
Limits: 256 KiB source, 20 tests, 8 second publication validation timeout.

The full bundle, including tests and severity configuration, is canonicalized as
JSON and SHA-256 hashed. JSON object key order and whitespace do not change the
digest; source text and test content do. Version and digest are tenant-scoped and
unique. Database triggers reject updates/deletes. Validation/audit failures
prevent publication. Read with `GET /api/v1/policies/{digest}` (`scans:read`).

Submit `policy_digest` on scans (CLI `-policy-digest`). If omitted, a built-in
baseline bundle is persisted and bound at submission, not looked up by a mutable
"latest" name at execution. The worker loads the exact digest and verifies its
content, materializes it in a private temporary directory, and evaluates OPA.
Policy capabilities disallow HTTP/DNS, runtime environment, current clock and
random builtins; subprocess deadline and output limits still apply. Publishers
are trusted security administrators; tests are evidence, not a proof that a
policy is correct for all workloads. Run the service with resource limits and
restricted outbound network access.

Existing legacy scans are retained but have `legacy-unknown` policy identity and
cannot authorize a release. Resubmit them to capture a verifiable policy snapshot.
Original counts/findings remain available. Scan summaries recompute gate from
the pinned bundle and counts; a missing/corrupt bundle errors. Image scans use
the bundle's severity gate; its Rego source applies only to Kubernetes manifests.

Reproduce: set `OPA_BIN=tools/opa.exe` (Windows) or a verified OPA binary, then
`go test ./...` and `go test -tags=integration ./integration`. The policy
integration creates its own MySQL schema, publishes two versions, rejects
mutation and cross-tenant use, and runs a real OPA worker against the first
version after the second is published.

# Scoped credentials and report trust

All `/api/` routes require database API keys. GET needs `scans:read`; POST scans
needs `scans:submit`. Imported Trivy reports additionally need `reports:import`.
There is no static environment-token fallback. Missing/invalid/expired/revoked
credentials return 401, insufficient scope 403, auth or audit storage outages 503.
Tenant and submitting subject come exclusively from the credential context.

After migration, an operator with database access can issue a short-lived key:

```powershell
docker compose run --rm --entrypoint key api -tenant acme -subject ci-checkout -scopes scans:read,scans:submit -ttl 24h
# To revoke: key -action revoke -tenant acme -id KEY_ID -subject operator-name
```

The command prints the token once; handle it as a secret, not as a log artifact.
Store only SHA-256 hashes of randomly generated 256-bit tokens. Use HTTPS at the
reverse proxy, restrict operator database credentials, rotate before expiry and
revoke old keys. API admission audits are intents; successful scan submission and
key lifecycle events are committed with their corresponding database mutation.
Audit storage is append-only through the application; DBA access can still alter
it, so production audit exports need a separate protected destination.

`submitted_by` and `evidence_source` are exposed in scan overviews. Old jobs are
`legacy-unknown`; server tool scans use `worker-tool`; uploaded reports use
`ci-import-unverified`. Authorization to import is not proof of report integrity.
An imported report can block on HIGH/CRITICAL findings, but absence of such
findings yields `error`, never `pass`, without independently verified evidence.
This stage has no signature/provenance verifier. Direct worker image/manifest
scans retain the existing gate behavior.

Upgrade: apply 000003, issue new keys, configure CI secrets, then deploy API and
worker. `SCAN_API_TOKENS` is no longer read. Do not put bearer values in `.env`
examples or request URLs. Preserve old data and the forward migrations on rollback.

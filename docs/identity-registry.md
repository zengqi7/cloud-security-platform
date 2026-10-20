# Identity and registry operations

API keys remain supported for CI and automation. To enable OIDC set the exact
OIDC_ISSUER_URL (HTTPS discovery) and OIDC_AUDIENCE. The provider must issue RFC
9068 signed JWT **access tokens** with `typ=at+jwt` or `application/at+jwt`, audience
of this API, issuer, subject and expiry. ID tokens and opaque access tokens are
not accepted. RS256/ES256 only. Signature/JWKS rotation is handled by go-oidc;
issuer, audience, expiry and not-before are checked. Discovery failure stops
startup; deploy replicas across fault domains and monitor IdP availability.

Provision identity using the operator-only `identity` binary with issuer,
subject, tenant, actor, explicit scopes and TTL. The SQL membership is looked up
on every request, so disabling it revokes authorization immediately. Token tenant,
group, role and scope claims cannot grant permissions. `(issuer, subject)` maps
to one tenant; separate identities/clients are needed for separate tenant contexts.
Human audit subjects use a stable issuer/subject hash to fit existing audit
limits. No JIT provisioning or unauthenticated role assignment is provided.
Use `identity --enabled=false` with the same identity to revoke and audit it.
Persistent rescan schedules require an API key because expiry/revocation is
rechecked by the scheduler; OIDC can submit scans and use permitted governance
APIs but cannot create API-key-bound schedules.

Registry requests use an optional `registry_credential` reference. Mount an
operator-managed JSON binding catalog (REGISTRY_BINDINGS_FILE), for example:

```json
[{"tenant":"acme","ref":"release-reader","registry":"registry.example.com","file":"release-reader"}]
```

Mount Docker config Secrets under the absolute REGISTRY_SECRET_DIR, with the
binding's single-component file name. Each file contains `auths` with a canonical
registry host key and base64 `username:password` auth. Helpers and executable
credential plugins are not used. Use pull-only short-lived robot credentials.
Bindings are checked for exact tenant and image registry host on every job.
Files are reloaded for rotation; jobs copy only the matched host into an isolated
0600 Docker config, shared by Trivy and Cosign for that job and removed afterward.
Workers have isolated ephemeral data volumes; no global credential environment
variables are accepted. Scanner children inherit an allowlist of environment
variables excluding control-plane/cloud secrets. Tool stderr is not persisted or
returned because registries/tools may echo secrets. Monitor failure counts and
inspect restricted provider audit logs for authentication or rate-limit errors.

Queue retries remain bounded at three attempts with delay, not infinite retries
against a throttled registry. Configure registry limits against worker concurrency
and verify real 401/403/429 behavior in staging. Kubernetes Secret updates must use
directory mounts (no subPath) to make rotation visible. Protect and clean worker
ephemeral disks after forced termination; never mount unrelated tenants' secrets
into a shared host home directory.

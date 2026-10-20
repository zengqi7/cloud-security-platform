Add OIDC RFC 9068 JWT access-token verification alongside API keys, with exact
issuer/API audience and operator-owned expiring SQL tenant/scope memberships.
Add an audited identity operator CLI and reject OIDC creation of recurring
schedules that require a durable API-key owner.

Add tenant/registry-host credential references backed by mounted Secrets,
per-job Docker config isolation and rotation. Restrict tool environment inheritance
and suppress raw tool stderr to avoid credential exposure.

Validation covers signature/JWKS rotation, wrong issuer/audience/expiry/type,
membership revocation, tenant/registry isolation and mounted credential rotation;
existing API-key regression and real SQL tests remain in CI. Live IdP/private
registry/429 scenarios require staging credentials and are not claimed executed.

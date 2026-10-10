# Security Policy

## Supported scope

The latest commit on `main` receives security fixes. CloudGuard is a
demonstration release-gate service and must be placed behind TLS and network
access controls for any shared deployment.

## Reporting

Use GitHub private vulnerability reporting when it is enabled for the
repository. Do not include credentials, private image names, scan reports, or
exploit details in a public issue.

Include the affected endpoint or component, reproduction steps, impact, and a
suggested mitigation when available.

## Deployment guidance

- Generate unique API tokens and database passwords; never reuse examples.
- Inject secrets through the deployment platform rather than committing
  `.env`.
- Restrict image registry credentials and outbound access available to the
  Worker.
- Accept imported Trivy reports only from trusted automation until signed
  provenance verification is implemented.
- A `pass` result only reflects the configured policy and current scanner
  database.

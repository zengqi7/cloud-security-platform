# CI release gate

CloudGuard submits asynchronous scans and returns 0 for pass, 2 for block, and
3 for failure, timeout, unknown state or incomplete/untrusted evidence. Never
use `continue-on-error` on the gate to authorize a release. Report imports need
`reports:import` in addition to submit/read and cannot authorize a clean release.

## CLI

Build `go build -o cloudguard ./cmd/cloudguard`. Set `CLOUDGUARD_API_URL` and
`CLOUDGUARD_TOKEN` through your secret store. Credentials are not accepted as
command-line arguments. Production requires HTTPS; loopback HTTP is for demos.
Redirects are rejected, including redirects to another credential destination.

```sh
cloudguard -kind manifest -manifest deploy/app.yaml -sarif cloudguard.sarif
cloudguard -kind image -target 'registry.example/app@sha256:REPLACE_WITH_DIGEST' -sarif cloudguard.sarif
cloudguard -scan-id SCAN_ID -sarif cloudguard.sarif
```

`-idempotency-key` safely reuses a submission; retry polling with `-scan-id` after
an interrupted CI job. Default timeout is 10 minutes, input limit 2 MiB, poll
interval 2 seconds. Kubernetes multi-document YAML is converted to a List
(maximum 100 documents). For a resumed manifest scan only supply `-manifest` if
it is the original matching file; the flag adds artifact context, not new input.

## GitHub composite Action

See `examples/cloudguard-ci.yml`. Replace the Action revision with the reviewed
immutable commit SHA before use. The API must be reachable from the runner; a
private endpoint requires a suitably configured self-hosted runner. The token
needs `scans:submit` and `scans:read`. Do not expose credentials on fork PR jobs.
Build and gate steps use environment variables and shell arrays for input.

Upload SARIF in a separate `if: always()` step so blocked builds still retain
evidence. Code scanning upload requires `security-events: write` and appropriate
GitHub plan/repository support. Upload permission must not confer gate approval.

SARIF 2.1.0 exports all findings across SQL pages, stable fingerprints, severities,
logical resource identity and gate evidence. Manifest CLI calls add a safe
repository-relative artifact URI. No source line numbers are fabricated. Image
and imported reports have only logical locations, which GitHub code scanning
may not display as inline annotations; retain the report as an artifact.

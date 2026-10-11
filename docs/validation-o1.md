# O1 validation evidence

Validation date: 2026-10-11. Local host: Windows amd64, Docker Desktop, Go 1.27.2, MySQL 8.4; scanner container includes OPA 1.21.1, Trivy 0.75.0, Cosign 3.1.3. Existing demonstration volumes were not deleted.

- Windows go test ./... and go vet ./... passed with real OPA configured.
- MySQL integration and Linux Docker go test -race -count=1 -tags=integration ./... passed, including unknown newer-schema refusal.
- Fresh Compose migration/API/worker deployment passed after separating privileged migrator credentials. Ordinary app-user trigger creation under MySQL binlog failed with 1419 and dirty metadata blocked startup, as intended.
- Dangerous Deployment smoke returned block with eight findings; safe Pod CLI with -assess returned succeeded/pass and a new immutable assessment, and produced SARIF 2.1.0.
- mysqldump including triggers/routines restored into an independent schema. cmd/migrate verified all eight migrations clean; one completed scan and all eight findings were preserved. This restoration snapshot preceded the separate safe-CLI exercise.
- govulncheck reported no vulnerabilities; release YAML passed actionlint and Compose/OpenAPI parsed.
- Local tool auto-discovery now selects the correct OS suffix, and worker data defaults to a relative data directory. Compose smoke's image option uses a fixed digest.

C7 already validated actual Trivy evidence and actual Cosign keyless success/wrong-identity rejection. SLSA subject/builder parsing has unit tests, but no external real-provenance success claim is made. No fixture is described as trusted tool execution.

Release archives are cross-compiled by scripts/package-release.sh and do not bundle external scanner binaries. Native macOS/Windows ARM runtime execution, production capacity, full certificate archival and a real version-tag publication/attestation retrieval remain unverified.

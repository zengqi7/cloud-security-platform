# Contributing

1. Create a focused branch from `main`.
2. Preserve tenant scoping, bounded inputs, lease fencing, and fail-closed gate
   behavior.
3. Run `go test -race ./...` and `go vet ./...`.
4. Run the OPA and MySQL integration tests plus
   `scripts/smoke-test.ps1` for scanner, policy, or queue changes.
5. Never commit `.env`, tokens, scan data, vulnerability databases, tools, or
   registry credentials.

Keep Trivy and OPA versions pinned and verify downloaded tool checksums when
upgrading.

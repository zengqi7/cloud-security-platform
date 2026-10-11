//go:build integration

package integration

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"errors"
	"os"
	"testing"
)

func TestImmutablePolicySnapshotsWithOPA(t *testing.T) {
	if os.Getenv("OPA_BIN") == "" {
		t.Skip("OPA_BIN required")
	}
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	p := auth.Principal{Tenant: "acme", Subject: "security", Scopes: []string{"policies:publish"}}
	pub := auth.WithPrincipal(ctx, p)
	safe, err := os.ReadFile("../examples/safe-pod.json")
	if err != nil {
		t.Fatal(err)
	}
	unsafe, err := os.ReadFile("../examples/unsafe-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	b := platform.DefaultPolicy()
	b.Version = "approved-v1"
	b.Tests = []platform.PolicyTest{{Manifest: safe, ExpectedGate: "pass"}, {Manifest: unsafe, ExpectedGate: "block"}}
	digest, err := s.PublishPolicy(pub, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishPolicy(ctx, b); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("unauthorized publish", err)
	}
	if _, err := s.LoadPolicy(ctx, "foreign", digest); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("foreign policy visible", err)
	}
	if _, err := db.Exec(`UPDATE policy_bundles SET version='tampered' WHERE tenant='acme'`); err == nil {
		t.Fatal("policy modified")
	}
	request := platform.Request{Kind: "manifest", Target: "release-app", Manifest: unsafe, PolicyDigest: digest}
	job, _, err := s.Submit(ctx, "acme", "release", request)
	if err != nil {
		t.Fatal(err)
	}
	b.Version = "approved-v2"
	b.Rego += "\n# new version\n"
	if _, err := s.PublishPolicy(pub, b); err != nil {
		t.Fatal(err)
	}
	scanner := platform.ToolScanner{OPA: os.Getenv("OPA_BIN"), WorkDir: t.TempDir()}
	if worked, err := (platform.Worker{Repo: s, Scanner: scanner}).Once(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	completed, err := s.Get(ctx, "acme", job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.PolicyDigest != digest || completed.Policy.Version != "approved-v1" || platform.Summarize(completed).Gate != "block" {
		t.Fatal("snapshot drift", completed)
	}
	reused, ok, err := s.Submit(ctx, "acme", "release", request)
	if err != nil || !ok || reused.ID != job.ID {
		t.Fatal("idempotency", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_audit_events WHERE action='policy:publish' AND outcome='succeeded'`).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}

//go:build integration

package integration

import (
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestInventoryDiffAndSBOMIntegrity(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	submit := func(key, target string, findings []platform.Finding) platform.Job {
		t.Helper()
		j, _, err := s.Submit(ctx, "acme", key, platform.Request{Kind: "image", Target: target, Asset: "checkout-api", Series: "prod"})
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := finishFixture(ctx, s, claimed, findings); err != nil {
			t.Fatal(err)
		}
		j, err = s.Get(ctx, "acme", j.ID)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	a := submit("a", "app:1", []platform.Finding{{RuleID: "CVE-1", Resource: "os", Package: "lib", Severity: "HIGH"}})
	b := submit("b", "app:2", nil)
	d, err := s.Diff(ctx, "acme", a.ID, b.ID)
	if err != nil || !d.Comparable || len(d.Resolved) != 1 || len(d.PossiblyFixed) != 1 {
		t.Fatal(d, err)
	}
	if _, err := s.Diff(ctx, "foreign", a.ID, b.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("foreign diff", err)
	}
	if _, err := db.Exec(`UPDATE scan_jobs SET scope_hash=REPEAT('0',64) WHERE id=?`, b.ID); err != nil {
		t.Fatal(err)
	}
	d, err = s.Diff(ctx, "acme", a.ID, b.ID)
	if err != nil || d.Comparable || len(d.Resolved) != 0 {
		t.Fatal(d, err)
	}
	// The completed image below intentionally lacks tool evidence: never authorize it.
	c, _, err := s.Submit(ctx, "acme", "missing", platform.Request{Kind: "image", Target: "app:3"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, claimed, nil, nil); err != nil {
		t.Fatal(err)
	}
	c, err = s.Get(ctx, "acme", c.ID)
	if err != nil || platform.Summarize(c).Gate != "error" {
		t.Fatal("missing evidence passed", err)
	}
	if _, err := s.SBOM(ctx, "acme", a.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal(err)
	}
	// Synthetic SBOM verifies storage integrity, not scanner authenticity.
	j, _, err := s.Submit(ctx, "acme", "sbom", platform.Request{Kind: "image", Target: "app:4"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bom := json.RawMessage(`{"bomFormat":"CycloneDX","components":[]}`)
	evidence := &platform.ScanEvidence{Tool: "fixture-scanner", ToolVersion: "1", Profile: "image:vuln-os-library:v1", Complete: true, CapturedAt: time.Now().UTC(), ArtifactDigest: "sha256:fixture", SBOMDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(bom))}
	if err := s.FinishEvidence(ctx, claimed, platform.ScanResult{Evidence: evidence, SBOM: bom}, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := s.SBOM(ctx, "acme", j.ID)
	if err != nil || string(stored) != string(bom) {
		t.Fatal(string(stored), err)
	}
	if _, err := s.SBOM(ctx, "foreign", j.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_jobs SET sbom_json=JSON_OBJECT('bomFormat','CycloneDX','components',JSON_ARRAY('tampered')) WHERE id=?`, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SBOM(ctx, "acme", j.ID); !errors.Is(err, platform.ErrState) {
		t.Fatal("tampered SBOM accepted", err)
	}
}

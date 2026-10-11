package platform

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRiskDiffRequiresComparableCompleteEvidence(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Minute)
	a := Job{ID: "a", Tenant: "test", AssetID: "asset", SeriesID: "series", ScopeHash: "scope", Status: "succeeded", CreatedAt: now, FinishedAt: &now, Request: Request{Kind: "image"}, Evidence: &ScanEvidence{Complete: true, Tool: "trivy", ToolVersion: "1", Profile: "vuln", ArtifactDigest: "old"}}
	b := a
	b.ID = "b"
	b.CreatedAt = later
	b.FinishedAt = &later
	e := *a.Evidence
	b.Evidence = &e
	b.Evidence.ArtifactDigest = "new"
	old := NormalizeFindings([]Finding{{RuleID: "CVE-1", Resource: "os", Package: "lib", Severity: "HIGH"}, {RuleID: "CVE-2", Resource: "os", Package: "lib2", Severity: "HIGH"}})
	new := NormalizeFindings([]Finding{{RuleID: "CVE-2", Resource: "os", Package: "lib2", Severity: "HIGH", InstalledVersion: "2"}, {RuleID: "CVE-3", Resource: "os", Package: "lib3", Severity: "LOW"}})
	d := CompareScans(a, b, old, new)
	if !d.Comparable || len(d.New) != 1 || len(d.Retained) != 1 || len(d.Resolved) != 1 || len(d.PossiblyFixed) != 1 {
		t.Fatal(d)
	}
	for _, change := range []func(*Job){func(j *Job) { j.Status = "failed" }, func(j *Job) { j.AssetID = "other" }, func(j *Job) { j.ScopeHash = "other" }, func(j *Job) { j.SeriesID = "other" }, func(j *Job) { j.Evidence = nil }, func(j *Job) { j.Evidence = &ScanEvidence{Complete: false} }} {
		c := b
		change(&c)
		d := CompareScans(a, c, old, nil)
		if d.Comparable || len(d.Resolved) != 0 {
			t.Fatal("false resolution", d)
		}
	}
}
func TestRealTrivyEvidence(t *testing.T) {
	target := os.Getenv("TRIVY_INTEGRATION_TARGET")
	if target == "" {
		t.Skip("explicit real pinned image required")
	}
	s, err := NewToolScanner(os.Getenv("SCAN_DATA_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	result, err := s.ScanEvidence(ctx, Request{Kind: "image", Target: target}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Evidence.Complete || result.Evidence.ArtifactDigest == "" || len(result.SBOM) == 0 || result.Evidence.SBOMDigest == "" {
		t.Fatal("missing real evidence")
	}
	t.Logf("Trivy=%s artifact=%s findings=%d SBOM bytes=%d", result.Evidence.ToolVersion, result.Evidence.ArtifactDigest, len(result.Findings), len(result.SBOM))
}

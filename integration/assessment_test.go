//go:build integration

package integration

import (
	"bytes"
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/cli"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAssessmentApprovalTTLAndImmutableEvidence(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	requestCtx := auth.WithPrincipal(ctx, auth.Principal{Tenant: "acme", Subject: "developer", Scopes: []string{"waivers:request", "waivers:approve"}})
	approveCtx := auth.WithPrincipal(ctx, auth.Principal{Tenant: "acme", Subject: "security", Scopes: []string{"waivers:approve"}})
	assessCtx := auth.WithPrincipal(ctx, auth.Principal{Tenant: "acme", Subject: "ci", Scopes: []string{"assessments:write"}})
	submitted, _, err := s.Submit(ctx, "acme", "release", platform.Request{Kind: "image", Target: "alpine:3.24"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, job, []platform.Finding{{RuleID: "CVE-test", Severity: "HIGH", Resource: "alpine", Package: "libc"}}, nil); err != nil {
		t.Fatal(err)
	}
	findings, _, err := s.Findings(ctx, "acme", job.ID, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := s.Assess(assessCtx, job.ID, "original")
	if err != nil || initial.Effective.Gate != "block" {
		t.Fatal(initial, err)
	}
	w, err := s.RequestWaiver(requestCtx, platform.WaiverRequest{ScanID: submitted.ID, Fingerprint: findings[0].Fingerprint, Reason: "temporary upstream exception with isolation", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideWaiver(requestCtx, w.ID, platform.WaiverDecision{Action: "approve", Reason: "self"}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("self approval", err)
	}
	if _, err := s.DecideWaiver(approveCtx, w.ID, platform.WaiverDecision{Action: "approve", Reason: "verified compensating controls"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := s.Assess(assessCtx, job.ID, "approved")
			if err != nil {
				t.Error(err)
				return
			}
			if a.Original.Gate != "block" || a.Effective.Gate != "pass" || len(a.AppliedWaivers) != 1 || a.AppliedWaivers[0].DecidedBy != "security" {
				t.Error("lost evidence", a)
			}
			ids <- a.ID
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		} else if first != id {
			t.Fatal("duplicate assessments")
		}
	}
	approved, err := s.GetAssessment(ctx, "acme", first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAssessment(ctx, "foreign", first); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("cross tenant", err)
	}
	if _, err := db.Exec(`UPDATE gate_assessments SET assessment_json=JSON_OBJECT() WHERE id=?`, first); err == nil {
		t.Fatal("mutable assessment")
	}
	_, token, err := s.CreateKey(ctx, "acme", "ci", []string{"scans:read", "assessments:write"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDGUARD_TOKEN", token)
	server := httptest.NewServer((&platform.API{Repo: s, Auth: s}).Handler())
	defer server.Close()
	var out, errs bytes.Buffer
	if code := cli.Run(ctx, []string{"-api", server.URL, "-scan-id", job.ID, "-assess"}, &out, &errs); code != 0 {
		t.Fatal(code, out.String(), errs.String())
	}
	if _, err := db.Exec(`UPDATE finding_waivers SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND) WHERE id=?`, w.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := s.Assess(assessCtx, job.ID, "expired")
	if err != nil || expired.Effective.Gate != "block" || len(expired.AppliedWaivers) != 0 {
		t.Fatal(expired, err)
	}
	retained, err := s.GetAssessment(ctx, "acme", approved.ID)
	if err != nil || retained.Effective.Gate != "pass" || retained.AppliedWaivers[0].ExpiresAt != approved.AppliedWaivers[0].ExpiresAt {
		t.Fatal("historical record changed", err)
	}
	originalJob, err := s.Get(ctx, "acme", job.ID)
	if err != nil || platform.Summarize(originalJob).Gate != "block" {
		t.Fatal("findings rewritten", err)
	}
	importJob, _, err := s.Submit(ctx, "acme", "import", platform.Request{Kind: "trivy_report", Target: "release", Report: []byte(`{"SchemaVersion":2,"Results":[]}`)})
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
	imported, err := s.Assess(assessCtx, importJob.ID, "import")
	if err != nil || imported.Effective.Gate != "error" {
		t.Fatal("untrusted import passed", imported, err)
	}
}

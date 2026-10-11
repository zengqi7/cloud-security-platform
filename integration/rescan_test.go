//go:build integration

package integration

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRescanDurabilityConcurrencyAndRevocation(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	_, token, err := s.CreateKey(ctx, "acme", "ci-rescan", []string{"scans:read", "scans:submit", "rescans:write"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	actor := auth.WithPrincipal(ctx, p)
	source, _, err := s.Submit(actor, "acme", "source", platform.Request{Kind: "image", Target: "app@sha256:" + strings.Repeat("a", 64), Asset: "checkout", Series: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := finishFixture(ctx, s, claimed, nil); err != nil {
		t.Fatal(err)
	}
	schedule, err := s.CreateRescan(actor, platform.RescanRequest{ScanID: source.ID, IntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRescan(ctx, "foreign", schedule.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE rescan_schedules SET next_run_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 5 DAY) WHERE id=?`, schedule.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := (platform.Store{DB: db}).EnqueueRescan(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var jobs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_jobs WHERE idempotency_key LIKE 'rescan:%'`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("duplicate period", jobs, err)
	}
	next, err := s.GetRescan(ctx, "acme", schedule.ID)
	if err != nil || !next.NextRunAt.After(time.Now().Add(59*time.Minute)) {
		t.Fatal("catch-up not coalesced", next, err)
	}
	if err := s.RevokeKey(ctx, "acme", p.KeyID, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE rescan_schedules SET next_run_at=UTC_TIMESTAMP(3) WHERE id=?`, schedule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueRescan(ctx); err != nil {
		t.Fatal(err)
	}
	next, err = s.GetRescan(ctx, "acme", schedule.ID)
	if err != nil || next.Enabled {
		t.Fatal("revoked schedule active", err)
	}
	if err := s.DisableRescan(actor, schedule.ID, "finished audit"); err != nil {
		t.Fatal(err)
	}
}
func TestFreshAssessmentDeadlineAndStaleEvidence(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	j, _, err := s.Submit(ctx, "acme", "fresh", platform.Request{Kind: "image", Target: "app:1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	updated := time.Now().UTC().Add(-48*time.Hour + 2*time.Minute)
	if err := s.FinishEvidence(ctx, c, platform.ScanResult{Evidence: &platform.ScanEvidence{Complete: true, DBUpdatedAt: &updated}}, nil); err != nil {
		t.Fatal(err)
	}
	actor := auth.WithPrincipal(ctx, auth.Principal{Tenant: "acme", Subject: "ci", Scopes: []string{"assessments:write"}})
	a, err := s.Assess(actor, j.ID, "near-expiry")
	if err != nil || a.Effective.Gate != "pass" || a.ValidUntil.After(updated.Add(48*time.Hour)) {
		t.Fatal(a, err)
	}
	if _, err := db.Exec(`UPDATE scan_jobs SET evidence_json=JSON_SET(evidence_json,'$.db_updated_at','2020-01-01T00:00:00Z') WHERE id=?`, j.ID); err != nil {
		t.Fatal(err)
	}
	stale, err := s.Assess(actor, j.ID, "fresh-key")
	if err != nil || stale.Effective.Gate != "error" {
		t.Fatal(stale, err)
	}
	historical, err := s.GetAssessment(ctx, "acme", a.ID)
	if err != nil || historical.Effective.Gate != "pass" {
		t.Fatal("history changed", err)
	}
}

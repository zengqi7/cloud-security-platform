//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
)

func TestStoreLifecycleIdempotencyAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("INTEGRATION_MYSQL_DSN")
	if dsn == "" {
		t.Skip("integration environment is not configured")
	}
	store, err := platform.OpenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tenant := "it-" + platform.NewID()
	request := platform.Request{Kind: "image", Target: "alpine:3.22"}
	first, reused, err := store.Submit(ctx, tenant, "release-42", request)
	if err != nil || reused {
		t.Fatalf("first submit: reused=%v err=%v", reused, err)
	}
	second, reused, err := store.Submit(ctx, tenant, "release-42", request)
	if err != nil || !reused || first.ID != second.ID {
		t.Fatalf("idempotent submit: first=%s second=%s reused=%v err=%v", first.ID, second.ID, reused, err)
	}
	_, _, err = store.Submit(ctx, tenant, "release-42", platform.Request{Kind: "image", Target: "busybox:1.37"})
	if !errors.Is(err, platform.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := store.Get(ctx, tenant+"-other", first.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("cross-tenant get returned %v", err)
	}
	claimed, err := store.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != first.ID || claimed.Status != "running" || claimed.Attempts != 1 || claimed.LeaseToken == "" {
		t.Fatalf("invalid claim: %+v", claimed)
	}
	findings := platform.NormalizeFindings([]platform.Finding{{
		RuleID:           "CVE-TEST",
		Severity:         "HIGH",
		Resource:         "alpine",
		Package:          "musl",
		InstalledVersion: "1",
		FixedVersion:     "2",
		Title:            "test",
	}})
	if err := finishFixture(ctx, store, claimed, findings); err != nil {
		t.Fatal(err)
	}
	completed, err := store.Get(ctx, tenant, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, total, err := store.Findings(ctx, tenant, first.ID, "HIGH", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "succeeded" || total != 1 || len(page) != 1 || platform.Summarize(completed).Gate != "block" {
		t.Fatalf("invalid completed job: %+v", completed)
	}
	if err := store.Finish(ctx, claimed, findings, nil); !errors.Is(err, platform.ErrLeaseLost) {
		t.Fatalf("stale lease was accepted: %v", err)
	}
}

func TestClaimDoesNotSortLargeRequestPayloads(t *testing.T) {
	db := isolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}

	// Force the production-default filesort failure with a small session buffer.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `SET SESSION sort_buffer_size=32768`); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"kind":"manifest","target":"large-batch","manifest":{"padding":"%s"}}`, strings.Repeat("x", 256*1024))
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("%032x", i+1)
		if _, err := db.ExecContext(ctx, `INSERT INTO scan_jobs(id,tenant,idempotency_key,request_hash,request_json,findings_json) VALUES(?,'large-queue',?,REPEAT('0',64),?,JSON_ARRAY())`, id, fmt.Sprintf("batch-%02d", i), payload); err != nil {
			t.Fatal(err)
		}
	}

	claimed, err := (platform.Store{DB: db}).Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != fmt.Sprintf("%032x", 1) || claimed.Status != "running" || len(claimed.Request.Manifest) < 256*1024 {
		t.Fatalf("unexpected claim: id=%s status=%s manifest_bytes=%d", claimed.ID, claimed.Status, len(claimed.Request.Manifest))
	}
}

func TestConcurrentClaimsRemainUnique(t *testing.T) {
	db := isolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	const workers = 8
	for i := 0; i < workers; i++ {
		if _, _, err := store.Submit(ctx, "claim-race", fmt.Sprintf("job-%d", i), platform.Request{Kind: "image", Target: "alpine:3.24"}); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	claimed := make(chan platform.Job, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				job, err := store.Claim(ctx)
				if errors.Is(err, platform.ErrNotFound) {
					select {
					case <-ctx.Done():
						errs <- ctx.Err()
						return
					case <-time.After(10 * time.Millisecond):
						continue
					}
				}
				if err != nil {
					errs <- err
					return
				}
				claimed <- job
				return
			}
		}()
	}
	close(start)
	wg.Wait()
	close(claimed)
	close(errs)
	for err := range errs {
		t.Errorf("claim failed: %v", err)
	}
	seen := make(map[string]bool, workers)
	for job := range claimed {
		if seen[job.ID] {
			t.Errorf("job claimed twice: %s", job.ID)
		}
		seen[job.ID] = true
	}
	if len(seen) != workers {
		t.Fatalf("claimed %d unique jobs, want %d", len(seen), workers)
	}
}

func TestConcurrentClaimAndFinishLeavesNoRunningLeases(t *testing.T) {
	db := isolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	const jobs = 64
	const workers = 8
	for i := 0; i < jobs; i++ {
		if _, _, err := store.Submit(ctx, "settle-race", fmt.Sprintf("job-%d", i), platform.Request{Kind: "image", Target: "alpine:3.24"}); err != nil {
			t.Fatal(err)
		}
	}

	var completed atomic.Int64
	var seen sync.Map
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for completed.Load() < jobs {
				job, err := store.Claim(ctx)
				if errors.Is(err, platform.ErrNotFound) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil {
					errCh <- err
					return
				}
				if _, loaded := seen.LoadOrStore(job.ID, true); loaded {
					errCh <- fmt.Errorf("job claimed twice: %s", job.ID)
					return
				}
				if err := store.Finish(ctx, job, nil, nil); err != nil {
					errCh <- err
					return
				}
				completed.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("worker failed: %v", err)
	}
	if completed.Load() != jobs {
		t.Fatalf("completed %d jobs, want %d", completed.Load(), jobs)
	}
	var succeeded, running int
	if err := db.QueryRowContext(ctx, `SELECT SUM(status='succeeded'),SUM(status='running') FROM scan_jobs WHERE tenant='settle-race'`).Scan(&succeeded, &running); err != nil {
		t.Fatal(err)
	}
	if succeeded != jobs || running != 0 {
		t.Fatalf("unexpected terminal state: succeeded=%d running=%d", succeeded, running)
	}
}

//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

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
	if err := store.Finish(ctx, claimed, findings, nil); err != nil {
		t.Fatal(err)
	}
	completed, err := store.Get(ctx, tenant, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "succeeded" || len(completed.Findings) != 1 || platform.Summarize(completed).Gate != "block" {
		t.Fatalf("invalid completed job: %+v", completed)
	}
	if err := store.Finish(ctx, claimed, findings, nil); !errors.Is(err, platform.ErrLeaseLost) {
		t.Fatalf("stale lease was accepted: %v", err)
	}
}

//go:build integration

package integration

import (
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	mysql "github.com/go-sql-driver/mysql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func isolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MySQL not configured")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	name := "csp_it_" + platform.NewID()
	if _, err := admin.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal(err)
	}
	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error(err)
		}
	})
	return db
}
func TestLegacyBackfillAndMigrationIntegrity(t *testing.T) {
	db := isolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := os.ReadFile(filepath.Join("..", "internal", "migration", "sql", "000001_jobs.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range migration.Statements(string(raw)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	findings := platform.NormalizeFindings([]platform.Finding{{RuleID: "CVE-OLD", Resource: "image", Severity: "HIGH"}, {RuleID: "CVE-OTHER", Resource: "image", Severity: "LOW"}})
	encoded, _ := json.Marshal(findings)
	id := platform.NewID()
	request := platform.Request{Kind: "image", Target: "alpine:3.24"}
	req, _ := json.Marshal(request)
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_jobs(id,tenant,idempotency_key,request_hash,request_json,status,findings_json) VALUES(?,'legacy','release',?,?,'succeeded',?)`, id, platform.RequestHash(request), req, encoded); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := migration.Apply(ctx, db); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := migration.Verify(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	job, err := store.Get(ctx, "legacy", id)
	if err != nil {
		t.Fatal(err)
	}
	if platform.Summarize(job).Counts["HIGH"] != 1 || platform.Summarize(job).Gate != "error" {
		t.Fatal("summary backfill", job)
	}
	page, total, err := store.Findings(ctx, "legacy", id, "", 1, 1)
	if err != nil || total != 2 || len(page) != 1 {
		t.Fatalf("page %v %d %v", page, total, err)
	}
	if _, _, err := store.Findings(ctx, "foreign", id, "", 0, 10); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("foreign page accepted", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET dirty=TRUE WHERE name='sql/000002_findings.sql'`); err != nil {
		t.Fatal(err)
	}
	if migration.Apply(ctx, db) == nil || migration.Verify(ctx, db) == nil {
		t.Fatal("dirty migration accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET dirty=FALSE,checksum=REPEAT('0',64) WHERE name='sql/000002_findings.sql'`); err != nil {
		t.Fatal(err)
	}
	if migration.Apply(ctx, db) == nil || migration.Verify(ctx, db) == nil {
		t.Fatal("checksum mismatch accepted")
	}
}

func TestExpiredFinalAttemptCommitsWithoutNextJob(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	job, _, err := store.Submit(ctx, "test", "crash", platform.Request{Kind: "image", Target: "alpine:3.24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_jobs SET status='running',attempts=3,lease_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND),lease_token='old' WHERE id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("expected empty queue", err)
	}
	ended, err := store.Get(ctx, "test", job.ID)
	if err != nil || ended.Status != "failed" || platform.Summarize(ended).Gate != "error" {
		t.Fatalf("terminal update rolled back: %+v %v", ended, err)
	}
}
func TestExpiredUnreclaimedLeaseCannotSettle(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	_, _, err := store.Submit(ctx, "test", "late", platform.Request{Kind: "image", Target: "alpine:3.24"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_jobs SET lease_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND) WHERE id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, job, []platform.Finding{}, nil); !errors.Is(err, platform.ErrLeaseLost) {
		t.Fatal("expired settlement accepted", err)
	}
}

//go:build integration

package integration

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScopedCredentialsAndUnverifiedReport(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	readID, readToken, err := store.CreateKey(ctx, "acme", "reader", []string{"scans:read"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, submitToken, err := store.CreateKey(ctx, "acme", "builder", []string{"scans:submit", "scans:read"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	importID, importToken, err := store.CreateKey(ctx, "acme", "trusted-ci", []string{"scans:submit", "scans:read", "reports:import"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&platform.API{Repo: store, Auth: store}).Handler())
	defer server.Close()
	call := func(method, path, token, body string) (int, []byte) {
		t.Helper()
		request, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, raw
	}
	image := `{"kind":"image","target":"alpine:3.24"}`
	if code, _ := call("POST", "/api/v1/scans", readToken, image); code != 403 {
		t.Fatal("reader submitted scan", code)
	}
	report := `{"kind":"trivy_report","target":"release","report":{"SchemaVersion":2,"Results":[]}}`
	if code, _ := call("POST", "/api/v1/scans", submitToken, report); code != 403 {
		t.Fatal("ordinary submitter imported report", code)
	}
	code, raw := call("POST", "/api/v1/scans", importToken, report)
	if code != 202 {
		t.Fatal(code, string(raw))
	}
	var submitted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &submitted); err != nil {
		t.Fatal(err)
	}
	job, err := store.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, job, nil, nil); err != nil {
		t.Fatal(err)
	}
	completed, err := store.Get(ctx, "acme", submitted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.SubmittedBy != "trusted-ci" || completed.EvidenceSource != "ci-import-unverified" || platform.Summarize(completed).Gate != "error" {
		t.Fatal("unverified report passed release gate", completed)
	}
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM scan_api_keys WHERE id=?`, readID).Scan(&stored); err != nil || stored == readToken || stored != auth.Hash(readToken) {
		t.Fatal("raw token persisted", err)
	}
	if err := store.RevokeKey(ctx, "foreign", readID, "operator"); err == nil {
		t.Fatal("foreign tenant revoked key")
	}
	if err := store.RevokeKey(ctx, "acme", readID, "operator"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call("GET", "/api/v1/scans", readToken, ""); code != 401 {
		t.Fatal("revoked token accepted", code)
	}
	if _, err := db.Exec(`UPDATE scan_api_keys SET expires_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND) WHERE id=?`, importID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, importToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("expired token accepted", err)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_audit_events WHERE action='scan:submit' AND outcome='succeeded' AND subject='trusted-ci'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing business success audit", audits, err)
	}
}

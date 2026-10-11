//go:build integration

package integration

import (
	"bytes"
	"cloud-security-platform/internal/cli"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCLIAndSARIFWithRealStorage(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := platform.Store{DB: db}
	_, token, err := store.CreateKey(ctx, "ci", "builder", []string{"scans:read", "scans:submit"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDGUARD_TOKEN", token)
	server := httptest.NewServer((&platform.API{Repo: store, Auth: store}).Handler())
	defer server.Close()
	for _, tc := range []struct {
		severity    string
		count, exit int
	}{{"HIGH", 205, 2}, {"LOW", 1, 0}, {"UNKNOWN", 1, 3}} {
		submitted, _, err := store.Submit(ctx, "ci", "", platform.Request{Kind: "image", Target: "alpine:3.24"})
		if err != nil {
			t.Fatal(err)
		}
		job, err := store.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		findings := make([]platform.Finding, tc.count)
		for i := range findings {
			findings[i] = platform.Finding{RuleID: fmt.Sprintf("CVE-%d", i), Resource: "alpine", Severity: tc.severity, Title: "dependency risk"}
		}
		if err := store.Finish(ctx, job, findings, nil); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "result.sarif")
		var out, errs bytes.Buffer
		code := cli.Run(ctx, []string{"-api", server.URL, "-scan-id", submitted.ID, "-sarif", path}, &out, &errs)
		if code != tc.exit {
			t.Fatal(code, errs.String(), out.String())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Version string `json:"version"`
			Runs    []struct {
				Results []struct {
					RuleID      string            `json:"ruleId"`
					Level       string            `json:"level"`
					Fingerprint map[string]string `json:"partialFingerprints"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != tc.count || doc.Runs[0].Results[0].Fingerprint["cloudguard/v1"] == "" {
			t.Fatal("incomplete SARIF", string(raw))
		}
	}
}

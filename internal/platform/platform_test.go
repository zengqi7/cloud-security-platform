package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTrivyAndGate(t *testing.T) {
	raw, err := os.ReadFile("../../examples/trivy-report.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := NormalizeTrivy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != "HIGH" || findings[0].FixedVersion != "1.1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	job := Job{Status: "succeeded", Findings: findings}
	if s := Summarize(job); s.Gate != "block" || s.Counts["HIGH"] != 1 {
		t.Fatalf("unsafe gate: %+v", s)
	}
	job.Status = "failed"
	if s := Summarize(job); s.Gate != "error" {
		t.Fatalf("failed scans must not pass: %+v", s)
	}
	for _, raw := range []string{`{}`, `{"SchemaVersion":2,"Results":null}`, `{"SchemaVersion":2,"Results":[]} {}`} {
		if _, err := NormalizeTrivy([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid report %s", raw)
		}
	}
}
func TestPolicyInputWorkloadsAndInitContainers(t *testing.T) {
	raw := json.RawMessage(`{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"reconcile"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"main","image":"app:1"}],"initContainers":[{"name":"init","image":"setup:1"}]}}}}}}`)
	input, err := PolicyInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	workloads := input["workloads"].([]map[string]any)
	if len(workloads) != 1 || len(workloads[0]["containers"].([]any)) != 2 || workloads[0]["resource"] != "CronJob/default/reconcile" {
		t.Fatalf("unexpected policy input: %+v", input)
	}
	if _, err := PolicyInput(json.RawMessage(`{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"x"}}`)); err == nil {
		t.Fatal("unsupported kinds must not yield a passing empty scan")
	}
}

type testAuth map[string]string

func (a testAuth) Authenticate(_ context.Context, token string) (auth.Principal, error) {
	for tenant, expected := range a {
		if token == expected {
			return auth.Principal{Tenant: tenant, Subject: "test", Scopes: []string{"scans:read", "scans:submit"}}, nil
		}
	}
	return auth.Principal{}, auth.ErrUnauthorized
}
func (testAuth) Audit(context.Context, auth.Principal, string, string, string) error { return nil }

type memoryRepo struct {
	job         Job
	tenant      string
	key         string
	submitCalls int
	getErr      error
}

func (m *memoryRepo) Ping(context.Context) error { return nil }
func (m *memoryRepo) Submit(_ context.Context, tenant, key string, r Request) (Job, bool, error) {
	m.tenant = tenant
	m.key = key
	m.submitCalls++
	return Job{ID: strings.Repeat("a", 32), Tenant: tenant, Request: r, Status: "queued"}, false, nil
}
func (m *memoryRepo) Get(_ context.Context, tenant, id string) (Job, error) {
	m.tenant = tenant
	if m.getErr != nil {
		return Job{}, m.getErr
	}
	if m.job.Tenant != tenant || m.job.ID != id {
		return Job{}, ErrNotFound
	}
	return m.job, nil
}
func (m *memoryRepo) List(_ context.Context, tenant string, limit int) ([]Job, error) {
	m.tenant = tenant
	return []Job{}, nil
}
func apiRequest(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Idempotency-Key", "release-42")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAPIAuthenticatesAndScopesTenant(t *testing.T) {
	repo := &memoryRepo{job: Job{ID: strings.Repeat("a", 32), Tenant: "beta", Status: "succeeded", Findings: []Finding{}}}
	api := &API{Repo: repo, Auth: testAuth{"acme": "acme-test-token-123", "beta": "beta-test-token-123"}}
	h := api.Handler()
	path := "/api/v1/scans/" + strings.Repeat("a", 32)
	if w := apiRequest(h, "GET", path, "", ""); w.Code != 401 {
		t.Fatalf("missing auth: %d", w.Code)
	}
	if w := apiRequest(h, "GET", path, "acme-test-token-123", ""); w.Code != 404 || repo.tenant != "acme" {
		t.Fatalf("cross-tenant disclosure: %d", w.Code)
	}
	if w := apiRequest(h, "GET", path+"/summary", "beta-test-token-123", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"gate":"pass"`) {
		t.Fatalf("owner cannot read: %d %s", w.Code, w.Body.String())
	}
}
func TestAPISubmitsAndRejectsMalformedBodies(t *testing.T) {
	repo := &memoryRepo{}
	api := &API{Repo: repo, Auth: testAuth{"acme": "acme-test-token-123"}}
	h := api.Handler()
	good := `{"kind":"image","target":"alpine:3.22"}`
	if w := apiRequest(h, "POST", "/api/v1/scans", "acme-test-token-123", good); w.Code != 202 || repo.key != "release-42" || repo.tenant != "acme" {
		t.Fatalf("submit failed: %d", w.Code)
	}
	for _, body := range []string{good + " {}", `{"kind":"image","target":"--help"}`, `{"kind":"image","target":"a","unknown":1}`, `{"kind":"image","target":"a","report":{}}`} {
		if w := apiRequest(h, "POST", "/api/v1/scans", "acme-test-token-123", body); w.Code != 400 {
			t.Fatalf("accepted invalid body %s: %d", body, w.Code)
		}
	}
	if repo.submitCalls != 1 {
		t.Fatal("invalid requests reached storage")
	}
}

type failingScanner struct{}

func (failingScanner) Scan(context.Context, Request) ([]Finding, error) {
	return nil, errors.New("tool unavailable")
}

type workRepo struct {
	job      Job
	savedErr error
	complete bool
}

func (m *workRepo) Claim(context.Context) (Job, error) { return m.job, nil }
func (m *workRepo) Finish(_ context.Context, _ Job, _ []Finding, err error) error {
	m.complete = true
	m.savedErr = err
	return nil
}
func TestWorkerPersistsFailure(t *testing.T) {
	repo := &workRepo{job: Job{ID: "scan", Attempts: 1}}
	worked, err := (Worker{Repo: repo, Scanner: failingScanner{}}).Once(context.Background())
	if err != nil || !worked || !repo.complete || repo.savedErr == nil {
		t.Fatal("scanner failure was silently marked successful")
	}
}
func TestOPAIntegration(t *testing.T) {
	binary := os.Getenv("OPA_BIN")
	if binary == "" {
		t.Skip("OPA_BIN is not configured")
	}
	scanner := ToolScanner{OPA: binary, Policy: "../../policies/baseline.rego"}
	for _, tc := range []struct {
		file   string
		unsafe bool
	}{{"unsafe-deployment.json", true}, {"safe-pod.json", false}} {
		raw, err := os.ReadFile("../../examples/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		findings, err := scanner.Scan(ctx, Request{Kind: "manifest", Target: tc.file, Manifest: raw})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if tc.unsafe && len(findings) < 7 {
			t.Fatalf("expected unsafe policy hits, got %+v", findings)
		}
		if !tc.unsafe && len(findings) != 0 {
			t.Fatalf("safe workload findings: %+v", findings)
		}
	}
}

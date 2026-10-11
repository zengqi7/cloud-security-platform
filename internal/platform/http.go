package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Repository interface {
	Submit(context.Context, string, string, Request) (Job, bool, error)
	Get(context.Context, string, string) (Job, error)
	List(context.Context, string, int) ([]Job, error)
	Ping(context.Context) error
}
type API struct {
	Repo      Repository
	Auth      auth.Repository
	Submitted atomic.Uint64
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.Repo.Ping(ctx); err != nil {
			respond(w, 503, map[string]string{"status": "degraded"})
			return
		}
		respond(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, "# TYPE cloudguard_scans_submitted_total counter\ncloudguard_scans_submitted_total "+strconv.FormatUint(a.Submitted.Load(), 10)+"\n")
	})
	mux.Handle("/api/", a.auth(http.HandlerFunc(a.route)))
	return mux
}

type tenantContextKey struct{}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			respond(w, 401, map[string]string{"error": "Bearer token required"})
			return
		}
		if a.Auth == nil {
			respond(w, 503, map[string]string{"error": "authentication unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		p, err := a.Auth.Authenticate(ctx, strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			status := 503
			if errors.Is(err, auth.ErrUnauthorized) {
				status = 401
			}
			respond(w, status, map[string]string{"error": "credential unavailable or invalid"})
			return
		}
		scope := "scans:read"
		if r.Method != http.MethodGet {
			scope = "scans:submit"
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/policies") && r.Method != http.MethodGet {
			scope = "policies:publish"
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/waivers" {
			scope = "waivers:request"
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/waivers/") {
			scope = "waivers:approve"
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/assessments") {
			scope = "assessments:write"
		}
		if !p.Allows(scope) {
			respond(w, 403, map[string]string{"error": "insufficient scope"})
			return
		}
		if err := a.Auth.Audit(ctx, p, r.Method, r.URL.Path, "admitted"); err != nil {
			respond(w, 503, map[string]string{"error": "audit unavailable"})
			return
		}
		ctx = auth.WithPrincipal(context.WithValue(ctx, tenantContextKey{}, p.Tenant), p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var scanID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (a *API) route(w http.ResponseWriter, r *http.Request) {
	tenant, _ := r.Context().Value(tenantContextKey{}).(string)
	if a.governance(w, r, tenant) {
		return
	}
	if r.URL.Path == "/api/v1/scans" {
		switch r.Method {
		case http.MethodPost:
			var req Request
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&req); err != nil {
				respond(w, 400, map[string]string{"error": "invalid request JSON (maximum 2 MiB)"})
				return
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				respond(w, 400, map[string]string{"error": "expected a single JSON object"})
				return
			}
			if err := Validate(req); err != nil {
				respond(w, 400, map[string]string{"error": err.Error()})
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if req.Kind == "trivy_report" {
				p, _ := auth.FromContext(r.Context())
				if !p.Allows("reports:import") {
					respond(w, 403, map[string]string{"error": "reports:import required"})
					return
				}
			}
			if len(key) > 128 {
				respond(w, 400, map[string]string{"error": "Idempotency-Key exceeds 128 bytes"})
				return
			}
			job, reused, err := a.Repo.Submit(r.Context(), tenant, key, req)
			if err != nil {
				a.failure(w, err)
				return
			}
			if !reused {
				a.Submitted.Add(1)
			}
			w.Header().Set("Location", "/api/v1/scans/"+job.ID)
			respond(w, 202, map[string]any{"id": job.ID, "status": job.Status, "reused": reused})
		case http.MethodGet:
			limit := 20
			if value := r.URL.Query().Get("limit"); value != "" {
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 || n > 100 {
					respond(w, 400, map[string]string{"error": "limit must be between 1 and 100"})
					return
				}
				limit = n
			}
			jobs, err := a.Repo.List(r.Context(), tenant, limit)
			if err != nil {
				a.failure(w, err)
				return
			}
			items := make([]map[string]any, 0, len(jobs))
			for _, job := range jobs {
				items = append(items, jobOverview(job))
			}
			respond(w, 200, map[string]any{"items": items, "count": len(items)})
		default:
			w.Header().Set("Allow", "GET, POST")
			respond(w, 405, map[string]string{"error": "method not allowed"})
		}
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || len(parts) > 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "scans" || !scanID.MatchString(parts[3]) {
		respond(w, 404, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		respond(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if len(parts) == 5 && parts[4] != "findings" && parts[4] != "summary" && parts[4] != "sarif" {
		respond(w, 404, map[string]string{"error": "not found"})
		return
	}
	job, err := a.Repo.Get(r.Context(), tenant, parts[3])
	if err != nil {
		a.failure(w, err)
		return
	}
	if len(parts) == 4 {
		respond(w, 200, jobOverview(job))
		return
	}
	if parts[4] == "sarif" {
		if job.Status != "succeeded" && job.Status != "failed" {
			respond(w, 409, map[string]string{"error": "scan not finished"})
			return
		}
		findings := job.Findings
		if repo, ok := a.Repo.(FindingRepository); ok {
			findings = []Finding{}
			for offset := 0; ; {
				page, total, err := repo.Findings(r.Context(), tenant, job.ID, "", offset, 100)
				if err != nil {
					a.failure(w, err)
					return
				}
				findings = append(findings, page...)
				offset += len(page)
				if offset >= total {
					break
				}
				if len(page) == 0 {
					respond(w, 500, map[string]string{"error": "incomplete findings export"})
					return
				}
			}
		}
		respond(w, 200, SARIF(job, findings))
		return
	}
	if parts[4] == "summary" {
		respond(w, 200, Summarize(job))
		return
	}
	severity := strings.ToUpper(r.URL.Query().Get("severity"))
	switch severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
	default:
		respond(w, 400, map[string]string{"error": "invalid severity"})
		return
	}
	offset, limit := 0, 50
	for key, dest := range map[string]*int{"offset": &offset, "limit": &limit} {
		if value := r.URL.Query().Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || (key == "limit" && (n < 1 || n > 100)) {
				respond(w, 400, map[string]string{"error": "invalid pagination"})
				return
			}
			*dest = n
		}
	}
	if repo, ok := a.Repo.(FindingRepository); ok {
		items, total, err := repo.Findings(r.Context(), tenant, job.ID, severity, offset, limit)
		if err != nil {
			a.failure(w, err)
			return
		}
		respond(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit})
		return
	}
	filtered := make([]Finding, 0)
	for _, f := range job.Findings {
		if severity == "" || f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total || end < offset {
		end = total
	}
	respond(w, 200, map[string]any{"items": filtered[offset:end], "total": total, "offset": offset, "limit": limit})
}
func jobOverview(j Job) map[string]any {
	return map[string]any{"id": j.ID, "tenant": j.Tenant, "kind": j.Request.Kind, "target": j.Request.Target, "status": j.Status, "attempts": j.Attempts, "error": j.Error, "created_at": j.CreatedAt, "finished_at": j.FinishedAt, "summary": Summarize(j), "submitted_by": j.SubmittedBy, "evidence_source": j.EvidenceSource, "policy_digest": j.PolicyDigest}
}
func (a *API) failure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrState) {
		respond(w, 409, map[string]string{"error": err.Error()})
		return
	}
	if errors.Is(err, ErrInvalid) {
		respond(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if errors.Is(err, auth.ErrUnauthorized) {
		respond(w, 403, map[string]string{"error": "insufficient scope"})
		return
	}
	if errors.Is(err, ErrNotFound) {
		respond(w, 404, map[string]string{"error": "not found"})
		return
	}
	if errors.Is(err, ErrConflict) {
		respond(w, 409, map[string]string{"error": ErrConflict.Error()})
		return
	}
	log.Printf("repository operation failed: %v", err)
	respond(w, 503, map[string]string{"error": "storage temporarily unavailable"})
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("response encode failed: %v", err)
	}
}

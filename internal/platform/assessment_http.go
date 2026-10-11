package platform

import (
	"context"
	"net/http"
	"strings"
)

type assessmentRepository interface {
	RequestWaiver(context.Context, WaiverRequest) (Waiver, error)
	DecideWaiver(context.Context, string, WaiverDecision) (Waiver, error)
	GetWaiver(context.Context, string, string) (Waiver, error)
	Assess(context.Context, string, string) (Assessment, error)
	GetAssessment(context.Context, string, string) (Assessment, error)
}

func (a *API) assessmentRoute(w http.ResponseWriter, r *http.Request, tenant string) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v1" {
		return false
	}
	relevant := parts[2] == "waivers" || parts[2] == "assessments" || (len(parts) == 5 && parts[2] == "scans" && parts[4] == "assessments")
	if !relevant {
		return false
	}
	repo, ok := a.Repo.(assessmentRepository)
	if !ok {
		respond(w, 503, map[string]string{"error": "governance storage unavailable"})
		return true
	}
	var result any
	var err error
	status := 200
	switch {
	case len(parts) == 3 && parts[2] == "waivers" && r.Method == http.MethodPost:
		var req WaiverRequest
		if decodeGovernance(w, r, &req) != nil {
			respond(w, 400, map[string]string{"error": "invalid waiver JSON"})
			return true
		}
		result, err = repo.RequestWaiver(r.Context(), req)
		status = 201
	case len(parts) == 4 && parts[2] == "waivers" && scanID.MatchString(parts[3]) && r.Method == http.MethodGet:
		result, err = repo.GetWaiver(r.Context(), tenant, parts[3])
	case len(parts) == 5 && parts[2] == "waivers" && scanID.MatchString(parts[3]) && parts[4] == "decision" && r.Method == http.MethodPost:
		var req WaiverDecision
		if decodeGovernance(w, r, &req) != nil {
			respond(w, 400, map[string]string{"error": "invalid decision JSON"})
			return true
		}
		result, err = repo.DecideWaiver(r.Context(), parts[3], req)
	case len(parts) == 5 && parts[2] == "scans" && scanID.MatchString(parts[3]) && r.Method == http.MethodPost:
		result, err = repo.Assess(r.Context(), parts[3], r.Header.Get("Idempotency-Key"))
		status = 201
	case len(parts) == 4 && parts[2] == "assessments" && scanID.MatchString(parts[3]) && r.Method == http.MethodGet:
		result, err = repo.GetAssessment(r.Context(), tenant, parts[3])
	default:
		respond(w, 404, map[string]string{"error": "not found"})
		return true
	}
	if err != nil {
		a.failure(w, err)
	} else {
		respond(w, status, result)
	}
	return true
}

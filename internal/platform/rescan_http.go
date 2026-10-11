package platform

import (
	"context"
	"net/http"
	"strings"
)

type rescanRepository interface {
	CreateRescan(context.Context, RescanRequest) (RescanSchedule, error)
	GetRescan(context.Context, string, string) (RescanSchedule, error)
	DisableRescan(context.Context, string, string) error
}

func (a *API) rescanRoute(w http.ResponseWriter, r *http.Request, tenant string) bool {
	if r.URL.Path != "/api/v1/rescans" && !strings.HasPrefix(r.URL.Path, "/api/v1/rescans/") {
		return false
	}
	repo, ok := a.Repo.(rescanRepository)
	if !ok {
		respond(w, 503, map[string]string{"error": "schedule storage unavailable"})
		return true
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var result any
	var err error
	status := 200
	switch {
	case len(parts) == 3 && r.Method == http.MethodPost:
		var req RescanRequest
		if decodeGovernance(w, r, &req) != nil {
			respond(w, 400, map[string]string{"error": "invalid schedule JSON"})
			return true
		}
		result, err = repo.CreateRescan(r.Context(), req)
		status = 201
	case len(parts) == 4 && scanID.MatchString(parts[3]) && r.Method == http.MethodGet:
		result, err = repo.GetRescan(r.Context(), tenant, parts[3])
	case len(parts) == 5 && scanID.MatchString(parts[3]) && parts[4] == "disable" && r.Method == http.MethodPost:
		var req struct {
			Reason string `json:"reason"`
		}
		if decodeGovernance(w, r, &req) != nil {
			respond(w, 400, map[string]string{"error": "reason required"})
			return true
		}
		err = repo.DisableRescan(r.Context(), parts[3], req.Reason)
		result = map[string]bool{"disabled": true}
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

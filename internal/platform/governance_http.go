package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func decodeGovernance(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("single JSON object required")
	}
	return nil
}
func (a *API) governance(w http.ResponseWriter, r *http.Request, tenant string) bool {
	if a.assessmentRoute(w, r, tenant) {
		return true
	}
	if r.URL.Path == "/api/v1/policies" && r.Method == http.MethodPost {
		var bundle PolicyBundle
		if err := decodeGovernance(w, r, &bundle); err != nil {
			respond(w, 400, map[string]string{"error": "invalid policy JSON"})
			return true
		}
		repo, ok := a.Repo.(interface {
			PublishPolicy(context.Context, PolicyBundle) (string, error)
		})
		if !ok {
			respond(w, 503, map[string]string{"error": "policy storage unavailable"})
			return true
		}
		digest, err := repo.PublishPolicy(r.Context(), bundle)
		if err != nil {
			a.failure(w, err)
			return true
		}
		respond(w, 201, map[string]string{"digest": digest, "version": bundle.Version})
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/policies/") && r.Method == http.MethodGet {
		digest := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
		if !digestPattern.MatchString(digest) {
			respond(w, 404, map[string]string{"error": "not found"})
			return true
		}
		repo, ok := a.Repo.(interface {
			LoadPolicy(context.Context, string, string) (PolicyBundle, error)
		})
		if !ok {
			respond(w, 503, map[string]string{"error": "policy storage unavailable"})
			return true
		}
		b, err := repo.LoadPolicy(r.Context(), tenant, digest)
		if err != nil {
			a.failure(w, err)
			return true
		}
		respond(w, 200, b)
		return true
	}
	return false
}

package platform

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

type healthRepo struct{ err error }

func (r healthRepo) Ping(context.Context) error { return r.err }
func TestWorkerHealth(t *testing.T) {
	h := &WorkerHealth{}
	check := func(path string, repo healthRepo, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		h.Handler(repo).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s: %d != %d", path, w.Code, want)
		}
	}
	check("/healthz", healthRepo{}, 503)
	h.Progress()
	h.ready.Store(true)
	check("/healthz", healthRepo{}, 200)
	check("/readyz", healthRepo{}, 200)
	check("/readyz", healthRepo{errors.New("offline")}, 503)
	check("/healthz", healthRepo{errors.New("offline")}, 200)
	h.lastProgress.Store(time.Now().Add(-180 * time.Second).UnixNano())
	check("/healthz", healthRepo{}, 503)
}

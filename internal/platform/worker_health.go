package platform

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"
)

// WorkerHealth observes loop progress, not scan success. Dependency outages
// change readiness; liveness must not cause a restart storm during DB failover.
type WorkerHealth struct {
	lastProgress atomic.Int64
	ready        atomic.Bool
}

func (h *WorkerHealth) Progress() { h.lastProgress.Store(time.Now().UnixNano()) }
func (h *WorkerHealth) Handler(repo interface{ Ping(context.Context) error }) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		last := h.lastProgress.Load()
		if last == 0 || time.Since(time.Unix(0, last)) > 175*time.Second {
			respond(w, 503, map[string]string{"status": "stalled"})
			return
		}
		respond(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if !h.ready.Load() || repo.Ping(ctx) != nil {
			respond(w, 503, map[string]string{"status": "not_ready"})
			return
		}
		respond(w, 200, map[string]string{"status": "ok"})
	})
	return mux
}

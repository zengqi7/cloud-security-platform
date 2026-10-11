package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGateFailClosed(t *testing.T) {
	t.Setenv("CLOUDGUARD_TOKEN", "test-secret")
	for _, tc := range []struct {
		status, gate string
		code         int
	}{{"succeeded", "pass", 0}, {"succeeded", "block", 2}, {"succeeded", "unknown", 3}, {"failed", "pass", 3}, {"queued", "pending", 3}, {"unrecognized", "pass", 3}, {"", "pass", 3}} {
		t.Run(tc.status+tc.gate, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Error("missing credential")
				}
				json.NewEncoder(w).Encode(map[string]any{"status": tc.status, "summary": map[string]string{"gate": tc.gate}})
			}))
			defer server.Close()
			var out, errs bytes.Buffer
			code := Run(context.Background(), []string{"-api", server.URL, "-scan-id", strings.Repeat("a", 32), "-timeout", "25ms", "-poll-interval", "1ms"}, &out, &errs)
			if code != tc.code {
				t.Fatalf("code %d want %d: %s", code, tc.code, errs.String())
			}
		})
	}
}

func TestResponseFailureAndRedirect(t *testing.T) {
	t.Setenv("CLOUDGUARD_TOKEN", "credential-never-print")
	for _, code := range []int{403, 302} {
		var sinkCalls int
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sinkCalls++ }))
		defer sink.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", sink.URL)
			w.WriteHeader(code)
			w.Write([]byte("credential-never-print"))
		}))
		defer server.Close()
		var out, errs bytes.Buffer
		if Run(context.Background(), []string{"-api", server.URL, "-scan-id", strings.Repeat("a", 32)}, &out, &errs) != 3 || sinkCalls != 0 || strings.Contains(errs.String(), "credential-never-print") {
			t.Fatal("redirect or credential leak", errs.String())
		}
	}
}

func TestManifestAndArtifact(t *testing.T) {
	raw, err := ManifestJSON([]byte("apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service\n"))
	if err != nil || !bytes.Contains(raw, []byte(`"kind":"List"`)) {
		t.Fatal(string(raw), err)
	}
	for _, input := range []string{"", "kind: Pod\nkind: Service", "- scalar"} {
		if _, err := ManifestJSON([]byte(input)); err == nil {
			t.Fatal("invalid accepted", input)
		}
	}
	document := map[string]any{"runs": []any{map[string]any{"results": []any{map[string]any{"locations": []any{map[string]any{}}}}}}}
	AttachArtifact(document, "../outside.yaml")
	raw, _ = json.Marshal(document)
	if bytes.Contains(raw, []byte("physicalLocation")) {
		t.Fatal("unsafe artifact")
	}
	AttachArtifact(document, "deploy/test file.yaml")
	raw, _ = json.Marshal(document)
	if !bytes.Contains(raw, []byte("test%20file.yaml")) || bytes.Contains(raw, []byte("startLine")) {
		t.Fatal(string(raw))
	}
}

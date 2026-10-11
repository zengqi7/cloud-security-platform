package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud-security-platform/internal/platform"
	"go.yaml.in/yaml/v3"
)

// Exit codes: 0 approved, 2 blocked, 3 error/timeout/incomplete evidence.
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("cloudguard", flag.ContinueOnError)
	flags.SetOutput(errOut)
	base := flags.String("api", os.Getenv("CLOUDGUARD_API_URL"), "HTTPS API URL (HTTP allowed only on loopback)")
	kind := flags.String("kind", "manifest", "manifest, image or trivy_report")
	target := flags.String("target", "", "asset target")
	manifest := flags.String("manifest", "", "Kubernetes YAML/JSON file")
	report := flags.String("report", "", "Trivy JSON report")
	id := flags.String("scan-id", "", "resume an existing scan")
	key := flags.String("idempotency-key", "", "submission request key")
	sarifPath := flags.String("sarif", "", "write SARIF report to this path")
	timeout := flags.Duration("timeout", 10*time.Minute, "total polling timeout")
	interval := flags.Duration("poll-interval", 2*time.Second, "poll interval")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 {
		return 3
	}
	fail := func(err error) int { fmt.Fprintln(errOut, err); return 3 }
	parsed, err := url.Parse(*base)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fail(errors.New("invalid API URL"))
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1")) {
		return fail(errors.New("HTTP API allowed only on loopback"))
	}
	token := os.Getenv("CLOUDGUARD_TOKEN")
	if token == "" {
		return fail(errors.New("CLOUDGUARD_TOKEN required"))
	}
	if *timeout <= 0 || *interval <= 0 {
		return fail(errors.New("timeout and poll-interval must be positive"))
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, path string, body any, result any) error {
		var input io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				return err
			}
			input = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(*base, "/")+path, input)
		if err != nil {
			return errors.New("request initialization failed")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if method == "POST" {
			req.Header.Set("Idempotency-Key", *key)
		}
		response, err := client.Do(req)
		if err != nil {
			return errors.New("API request failed or timed out")
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("API returned HTTP %d", response.StatusCode)
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
		if err := decoder.Decode(result); err != nil {
			return errors.New("invalid or oversized API response")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return errors.New("trailing API response")
		}
		return nil
	}
	if *id == "" {
		req := platform.Request{Kind: *kind, Target: *target}
		if *manifest != "" {
			raw, err := readBounded(*manifest)
			if err != nil {
				return fail(err)
			}
			req.Manifest, err = ManifestJSON(raw)
			if err != nil {
				return fail(err)
			}
			if req.Target == "" {
				req.Target = filepath.Base(*manifest)
			}
		}
		if *report != "" {
			raw, err := readBounded(*report)
			if err != nil {
				return fail(err)
			}
			req.Report = raw
		}
		if err := platform.Validate(req); err != nil {
			return fail(err)
		}
		var submitted struct {
			ID string `json:"id"`
		}
		if err := request("POST", "/api/v1/scans", req, &submitted); err != nil {
			return fail(err)
		}
		*id = submitted.ID
	}
	if len(*id) != 32 || strings.Trim(*id, "0123456789abcdef") != "" {
		return fail(errors.New("invalid scan ID"))
	}
	var job struct {
		Status  string           `json:"status"`
		Summary platform.Summary `json:"summary"`
	}
	for {
		job.Status = ""
		job.Summary = platform.Summary{}
		if err := request("GET", "/api/v1/scans/"+*id, nil, &job); err != nil {
			return fail(err)
		}
		if job.Status == "succeeded" || job.Status == "failed" {
			break
		}
		if job.Status != "queued" && job.Status != "running" {
			return fail(errors.New("unknown scan state; no release approval"))
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(errors.New("scan timed out; no release approval"))
		case <-timer.C:
		}
	}
	if *sarifPath != "" {
		var document map[string]any
		if err := request("GET", "/api/v1/scans/"+*id+"/sarif", nil, &document); err != nil {
			return fail(err)
		}
		if *manifest != "" {
			AttachArtifact(document, *manifest)
		}
		raw, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(*sarifPath, append(raw, '\n'), 0600); err != nil {
			return fail(errors.New("SARIF output cannot be written"))
		}
	}
	json.NewEncoder(out).Encode(map[string]any{"scan_id": *id, "status": job.Status, "gate": job.Summary.Gate, "reason": job.Summary.Reason})
	if job.Status != "succeeded" {
		return 3
	}
	switch job.Summary.Gate {
	case "pass":
		return 0
	case "block":
		return 2
	default:
		return 3
	}
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input file cannot be opened")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("input exceeds 2 MiB")
	}
	return raw, nil
}

func ManifestJSON(raw []byte) (json.RawMessage, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	resources := []map[string]any{}
	for {
		var resource map[string]any
		err := decoder.Decode(&resource)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid Kubernetes YAML")
		}
		if resource == nil {
			continue
		}
		resources = append(resources, resource)
		if len(resources) > 100 {
			return nil, errors.New("maximum 100 YAML documents")
		}
	}
	if len(resources) == 0 {
		return nil, errors.New("empty manifest")
	}
	if len(resources) == 1 {
		return json.Marshal(resources[0])
	}
	return json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": resources})
}

func AttachArtifact(document map[string]any, path string) {
	path = filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") {
		return
	}
	uri := (&url.URL{Path: path}).String()
	runs, _ := document["runs"].([]any)
	for _, raw := range runs {
		run, _ := raw.(map[string]any)
		results, _ := run["results"].([]any)
		for _, raw := range results {
			result, _ := raw.(map[string]any)
			locations, _ := result["locations"].([]any)
			for _, raw := range locations {
				location, _ := raw.(map[string]any)
				location["physicalLocation"] = map[string]any{"artifactLocation": map[string]string{"uri": uri}}
			}
		}
	}
}

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Scanner interface {
	Scan(context.Context, Request) ([]Finding, error)
}
type ToolScanner struct{ Trivy, OPA, Policy, CacheDir, WorkDir string }
type boundedBuffer struct {
	bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("scanner output exceeded limit")
	}
	return b.Buffer.Write(p)
}
func runTool(ctx context.Context, input []byte, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	stdout := &boundedBuffer{max: 16 << 20}
	stderr := &boundedBuffer{max: 16 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("scanner failed: %w: %.1024s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}
func (s ToolScanner) Scan(ctx context.Context, r Request) ([]Finding, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	switch r.Kind {
	case "image":
		raw, err := runTool(ctx, nil, s.Trivy, "image", "--image-src", "remote", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", "2m", "--cache-dir", s.CacheDir, "--", r.Target)
		if err != nil {
			return nil, err
		}
		return NormalizeTrivy(raw)
	case "trivy_report":
		return NormalizeTrivy(r.Report)
	case "manifest":
		input, err := PolicyInput(r.Manifest)
		if err != nil {
			return nil, err
		}
		rawInput, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		raw, err := runTool(ctx, rawInput, s.OPA, "eval", "--stdin-input", "--data", s.Policy, "--format=json", "data.cloudguard.findings")
		if err != nil {
			return nil, err
		}
		var result struct {
			Result []struct {
				Expressions []struct {
					Value []Finding `json:"value"`
				} `json:"expressions"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("invalid OPA response: %w", err)
		}
		if len(result.Result) != 1 || len(result.Result[0].Expressions) != 1 || result.Result[0].Expressions[0].Value == nil {
			return nil, errors.New("OPA policy returned undefined findings")
		}
		return NormalizeFindings(result.Result[0].Expressions[0].Value), nil
	}
	return nil, errors.New("unsupported scan")
}

func NormalizeTrivy(raw []byte) ([]Finding, error) {
	var report struct {
		SchemaVersion int `json:"SchemaVersion"`
		Results       []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				ID        string `json:"VulnerabilityID"`
				Package   string `json:"PkgName"`
				Installed string `json:"InstalledVersion"`
				Fixed     string `json:"FixedVersion"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&report); err != nil {
		return nil, fmt.Errorf("invalid Trivy JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("expected a single Trivy report")
	}
	if report.SchemaVersion != 2 || report.Results == nil {
		return nil, errors.New("expected Trivy SchemaVersion 2 with Results")
	}
	findings := make([]Finding, 0)
	for _, result := range report.Results {
		if result.Target == "" {
			return nil, errors.New("Trivy result is missing Target")
		}
		for _, v := range result.Vulnerabilities {
			if v.ID == "" || v.Package == "" {
				return nil, errors.New("incomplete vulnerability record")
			}
			recommendation := "No fixed version reported; evaluate upgrade or mitigation and rescan"
			if v.Fixed != "" {
				recommendation = "Upgrade to a vendor-supported fixed version: " + v.Fixed
			}
			findings = append(findings, Finding{RuleID: v.ID, Severity: v.Severity, Resource: result.Target, Package: v.Package, InstalledVersion: v.Installed, FixedVersion: v.Fixed, Title: v.Title, Recommendation: recommendation})
		}
	}
	return NormalizeFindings(findings), nil
}

// Kubernetes JSON is accepted directly; YAML can be converted with kubectl --dry-run=client -o json.
func PolicyInput(raw json.RawMessage) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return nil, errors.New("manifest must be a Kubernetes JSON object")
	}
	resources := []map[string]any{root}
	if root["kind"] == "List" {
		resources = nil
		items, ok := root["items"].([]any)
		if !ok || len(items) == 0 || len(items) > 100 {
			return nil, errors.New("List must contain 1 to 100 resources")
		}
		for _, v := range items {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("invalid List item")
			}
			resources = append(resources, m)
		}
	}
	workloads := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		kind, _ := resource["kind"].(string)
		api, _ := resource["apiVersion"].(string)
		metadata := object(resource["metadata"])
		name, _ := metadata["name"].(string)
		if api == "" || name == "" {
			return nil, errors.New("apiVersion and metadata.name are required")
		}
		var spec map[string]any
		switch kind {
		case "Pod":
			spec = object(resource["spec"])
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
			spec = object(object(object(resource["spec"])["template"])["spec"])
		case "CronJob":
			spec = object(object(object(object(object(resource["spec"])["jobTemplate"])["spec"])["template"])["spec"])
		default:
			return nil, fmt.Errorf("unsupported workload kind %q", kind)
		}
		containers, ok := spec["containers"].([]any)
		if !ok || len(containers) == 0 {
			return nil, errors.New("workload must contain containers")
		}
		all := append([]any{}, containers...)
		for _, key := range []string{"initContainers", "ephemeralContainers"} {
			if extra, ok := spec[key].([]any); ok {
				all = append(all, extra...)
			}
		}
		for _, v := range all {
			c, ok := v.(map[string]any)
			if !ok || c["name"] == nil || c["image"] == nil {
				return nil, errors.New("container name and image are required")
			}
		}
		ns, _ := metadata["namespace"].(string)
		if ns == "" {
			ns = "default"
		}
		workloads = append(workloads, map[string]any{"resource": kind + "/" + ns + "/" + name, "spec": spec, "containers": all})
	}
	return map[string]any{"workloads": workloads}, nil
}
func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func NewToolScanner(root string) (ToolScanner, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return ToolScanner{}, err
	}
	for _, name := range []string{"work", "trivy-cache"} {
		if err := os.MkdirAll(filepath.Join(abs, name), 0700); err != nil {
			return ToolScanner{}, err
		}
	}
	trivy := os.Getenv("TRIVY_BIN")
	if trivy == "" {
		trivy = localTool("trivy")
	}
	opa := os.Getenv("OPA_BIN")
	if opa == "" {
		opa = localTool("opa")
	}
	policy := os.Getenv("OPA_POLICY")
	if policy == "" {
		policy = filepath.Join("policies", "baseline.rego")
	}
	if strings.TrimSpace(policy) == "" {
		return ToolScanner{}, errors.New("OPA policy is required")
	}
	return ToolScanner{Trivy: trivy, OPA: opa, Policy: policy, CacheDir: filepath.Join(abs, "trivy-cache"), WorkDir: filepath.Join(abs, "work")}, nil
}

func localTool(name string) string {
	for _, candidate := range []string{
		filepath.Join("tools", name+".exe"),
		filepath.Join("tools", name),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return name
}

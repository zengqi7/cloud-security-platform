package platform

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/policies"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid governance request")

type PolicyTest struct {
	Manifest     json.RawMessage `json:"manifest"`
	ExpectedGate string          `json:"expected_gate"`
}
type PolicyBundle struct {
	Version         string       `json:"version"`
	Rego            string       `json:"rego"`
	BlockSeverities []string     `json:"block_severities"`
	Tests           []PolicyTest `json:"tests"`
}

func (b PolicyBundle) Digest() string {
	raw, _ := json.Marshal(b)
	var canonical any
	_ = json.Unmarshal(raw, &canonical)
	raw, _ = json.Marshal(canonical)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func DefaultPolicy() PolicyBundle {
	return PolicyBundle{Version: "baseline-v1", Rego: policies.Baseline, BlockSeverities: []string{"CRITICAL", "HIGH"}, Tests: []PolicyTest{}}
}

var policyVersion = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (b PolicyBundle) Validate(ctx context.Context, opa string) error {
	if !policyVersion.MatchString(b.Version) || len(b.Rego) == 0 || len(b.Rego) > 256<<10 || len(b.Tests) < 2 || len(b.Tests) > 20 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, severity := range b.BlockSeverities {
		if !slices.Contains([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, severity) || seen[severity] {
			return ErrInvalid
		}
		seen[severity] = true
	}
	if !seen["HIGH"] || !seen["CRITICAL"] {
		return fmt.Errorf("%w: HIGH and CRITICAL cannot be disabled", ErrInvalid)
	}
	pass, block := false, false
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, test := range b.Tests {
		if test.ExpectedGate != "pass" && test.ExpectedGate != "block" {
			return ErrInvalid
		}
		findings, err := evaluateBundle(ctx, opa, "", b, test.Manifest)
		if err != nil {
			return fmt.Errorf("%w: policy compilation or test failed", ErrInvalid)
		}
		if Summarize(Job{Status: "succeeded", Request: Request{Kind: "manifest"}, Findings: findings, Policy: &b}).Gate != test.ExpectedGate {
			return fmt.Errorf("%w: policy test mismatch", ErrInvalid)
		}
		pass = pass || test.ExpectedGate == "pass"
		block = block || test.ExpectedGate == "block"
	}
	if !pass || !block {
		return fmt.Errorf("%w: pass and block test cases required", ErrInvalid)
	}
	return nil
}

// Restrict policy builtins that can expose environment or perform network I/O.
func evaluateBundle(ctx context.Context, opa, work string, b PolicyBundle, manifest json.RawMessage) ([]Finding, error) {
	dir, err := os.MkdirTemp(work, "policy-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	policy := filepath.Join(dir, "bundle.rego")
	capPath := filepath.Join(dir, "capabilities.json")
	if err := os.WriteFile(policy, []byte(b.Rego), 0600); err != nil {
		return nil, err
	}
	raw, err := runTool(ctx, nil, opa, "capabilities", "--current")
	if err != nil {
		return nil, err
	}
	var capabilities map[string]any
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		return nil, err
	}
	builtins, _ := capabilities["builtins"].([]any)
	filtered := []any{}
	for _, raw := range builtins {
		m, _ := raw.(map[string]any)
		name, _ := m["name"].(string)
		if name == "http.send" || name == "net.lookup_ip_addr" || name == "opa.runtime" || name == "time.now_ns" || strings.HasPrefix(name, "rand.") {
			continue
		}
		filtered = append(filtered, m)
	}
	capabilities["builtins"] = filtered
	capabilities["allow_net"] = []string{}
	raw, err = json.Marshal(capabilities)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(capPath, raw, 0600); err != nil {
		return nil, err
	}
	return (ToolScanner{OPA: opa, Policy: policy, Capabilities: capPath}).Scan(ctx, Request{Kind: "manifest", Target: "policy-test", Manifest: manifest})
}
func (s Store) PublishPolicy(ctx context.Context, b PolicyBundle) (string, error) {
	p, ok := auth.FromContext(ctx)
	if !ok || !p.Allows("policies:publish") {
		return "", auth.ErrUnauthorized
	}
	opa := os.Getenv("OPA_BIN")
	if opa == "" {
		opa = localTool("opa")
	}
	if err := b.Validate(ctx, opa); err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	raw, _ := json.Marshal(b)
	digest := b.Digest()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_bundles(tenant,digest,version,bundle_json,published_by) VALUES(?,?,?,?,?)`, p.Tenant, digest, b.Version, raw, p.Subject); err != nil {
		return "", err
	}
	if err := auditTx(ctx, tx, p, "policy:publish", digest); err != nil {
		return "", err
	}
	return digest, tx.Commit()
}
func auditTx(ctx context.Context, tx *sql.Tx, p auth.Principal, action, resource string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,?,?,?,?,'succeeded')`, p.Tenant, p.KeyID, p.Subject, action, resource)
	return err
}
func (s Store) LoadPolicy(ctx context.Context, tenant, digest string) (PolicyBundle, error) {
	var b PolicyBundle
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT bundle_json FROM policy_bundles WHERE tenant=? AND digest=?`, tenant, digest).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	if err != nil {
		return b, err
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		return b, err
	}
	if b.Digest() != digest {
		return b, errors.New("policy digest mismatch")
	}
	return b, nil
}

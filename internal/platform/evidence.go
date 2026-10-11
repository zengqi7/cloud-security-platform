package platform

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ScanEvidence struct {
	SupplyChain    *SupplyChainEvidence `json:"supply_chain,omitempty"`
	Tool           string               `json:"tool"`
	ToolVersion    string               `json:"tool_version"`
	Profile        string               `json:"profile"`
	ArtifactDigest string               `json:"artifact_digest"`
	Complete       bool                 `json:"complete"`
	CapturedAt     time.Time            `json:"captured_at"`
	SBOMDigest     string               `json:"sbom_digest,omitempty"`
	DBUpdatedAt    *time.Time           `json:"db_updated_at,omitempty"`
}
type ScanResult struct {
	Findings []Finding
	Evidence *ScanEvidence
	SBOM     json.RawMessage
}

func scanProfile(kind string) string {
	switch kind {
	case "image":
		return "image:vuln-os-library:v1"
	case "manifest":
		return "k8s-workloads:rego:v1"
	default:
		return "unverified-import:v1"
	}
}
func hashBytes(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

var imageDigest = regexp.MustCompile(`@sha256:([a-f0-9]{64})$`)

func (s ToolScanner) ScanEvidence(ctx context.Context, r Request, b PolicyBundle) (ScanResult, error) {
	return s.scanEvidence(ctx, r, b, TrustPolicy{Mode: "disabled"})
}
func (s ToolScanner) scanEvidence(ctx context.Context, r Request, b PolicyBundle, trust TrustPolicy) (ScanResult, error) {
	evidence := &ScanEvidence{Profile: scanProfile(r.Kind), CapturedAt: time.Now().UTC()}
	result := ScanResult{Evidence: evidence}
	switch r.Kind {
	case "manifest":
		raw, err := runTool(ctx, nil, s.OPA, "version")
		if err != nil {
			return result, err
		}
		evidence.Tool = "opa"
		evidence.ToolVersion = strings.TrimSpace(string(raw))
		var canonical any
		if err := json.Unmarshal(r.Manifest, &canonical); err != nil {
			return result, err
		}
		raw, err = json.Marshal(canonical)
		if err != nil {
			return result, err
		}
		evidence.ArtifactDigest = "sha256:" + hashBytes(raw)
		result.Findings, err = evaluateBundle(ctx, s.OPA, s.WorkDir, b, r.Manifest)
		evidence.Complete = err == nil
		return result, err
	case "image":
		match := imageDigest.FindStringSubmatch(r.Target)
		if match == nil {
			return result, errors.New("release scans require a sha256-pinned image target")
		}
		version, err := runTool(ctx, nil, s.Trivy, "--version", "--format", "json")
		if err != nil {
			return result, err
		}
		var v struct {
			Version string `json:"Version"`
		}
		if err := json.Unmarshal(version, &v); err != nil || v.Version == "" {
			return result, errors.New("Trivy version unavailable")
		}
		evidence.Tool = "trivy"
		evidence.ToolVersion = v.Version
		evidence.SupplyChain, err = verifySupplyChain(ctx, r.Target, trust)
		if err != nil {
			return result, err
		}
		if _, err = runTool(ctx, nil, s.Trivy, "image", "--download-db-only", "--quiet", "--cache-dir", s.CacheDir); err != nil {
			return result, err
		}
		dbTime, err := readDBUpdatedAt(s.CacheDir)
		if err != nil {
			return result, err
		}
		evidence.DBUpdatedAt = &dbTime
		if _, fresh := evidenceDeadline(Job{Request: r, Evidence: evidence}, time.Now().UTC()); !fresh {
			return result, errors.New("vulnerability DB is stale")
		}
		raw, err := runTool(ctx, nil, s.Trivy, "image", "--skip-db-update", "--image-src", "remote", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", "2m", "--cache-dir", s.CacheDir, "--", r.Target)
		if err != nil {
			return result, err
		}
		var report struct {
			Metadata struct {
				RepoDigests []string `json:"RepoDigests"`
			} `json:"Metadata"`
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			return result, err
		}
		verified := false
		for _, ref := range report.Metadata.RepoDigests {
			if strings.HasSuffix(ref, "@sha256:"+match[1]) {
				verified = true
			}
		}
		if !verified {
			return result, errors.New("Trivy report did not confirm requested image digest")
		}
		evidence.ArtifactDigest = "sha256:" + match[1]
		result.Findings, err = NormalizeTrivy(raw)
		if err != nil {
			return result, err
		}
		result.SBOM, err = runTool(ctx, nil, s.Trivy, "image", "--image-src", "remote", "--format", "cyclonedx", "--quiet", "--timeout", "1m", "--cache-dir", s.CacheDir, "--", r.Target)
		if err != nil {
			return result, err
		}
		var bom struct {
			Format string `json:"bomFormat"`
		}
		if err := json.Unmarshal(result.SBOM, &bom); err != nil || bom.Format != "CycloneDX" {
			return result, errors.New("invalid CycloneDX SBOM")
		}
		var canonical any
		if err := json.Unmarshal(result.SBOM, &canonical); err != nil {
			return result, err
		}
		result.SBOM, err = json.Marshal(canonical)
		if err != nil {
			return result, err
		}
		evidence.SBOMDigest = "sha256:" + hashBytes(result.SBOM)
		after, err := readDBUpdatedAt(s.CacheDir)
		if err != nil || !after.Equal(dbTime) {
			return result, errors.New("vulnerability DB changed during scan; retry required")
		}
		evidence.Complete = true
		return result, nil
	case "trivy_report":
		findings, err := NormalizeTrivy(r.Report)
		result.Findings = findings
		evidence.Tool = "unverified-import"
		evidence.ToolVersion = "unknown"
		evidence.Complete = false
		return result, err
	}
	return result, errors.New("unsupported evidence profile")
}
func readDBUpdatedAt(cache string) (time.Time, error) {
	raw, err := os.ReadFile(filepath.Join(cache, "db", "metadata.json"))
	if err != nil {
		return time.Time{}, errors.New("vulnerability DB metadata unavailable")
	}
	var meta struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(raw, &meta) != nil || meta.UpdatedAt.IsZero() {
		return time.Time{}, errors.New("invalid vulnerability DB UpdatedAt")
	}
	return meta.UpdatedAt.UTC(), nil
}

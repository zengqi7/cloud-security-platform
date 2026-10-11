package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("idempotency key reused with different request")
var ErrLeaseLost = errors.New("scan lease lost")

type Request struct {
	Kind     string          `json:"kind"`
	Target   string          `json:"target"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
	Report   json.RawMessage `json:"report,omitempty"`
}
type Job struct {
	ID             string     `json:"id"`
	Tenant         string     `json:"tenant"`
	Status         string     `json:"status"`
	Request        Request    `json:"request"`
	Attempts       int        `json:"attempts"`
	Error          string     `json:"error,omitempty"`
	Findings       []Finding  `json:"findings"`
	CreatedAt      time.Time  `json:"created_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	LeaseToken     string     `json:"-"`
	StoredSummary  *Summary   `json:"-"`
	SubmittedBy    string     `json:"submitted_by"`
	EvidenceSource string     `json:"evidence_source"`
}
type Finding struct {
	Fingerprint      string `json:"fingerprint"`
	RuleID           string `json:"rule_id"`
	Severity         string `json:"severity"`
	Resource         string `json:"resource"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Title            string `json:"title"`
	Recommendation   string `json:"recommendation"`
}
type Summary struct {
	Counts map[string]int `json:"counts"`
	Gate   string         `json:"gate"`
	Reason string         `json:"reason"`
}

func Summarize(job Job) Summary {
	s := Summary{Counts: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}, Gate: "pending", Reason: "scan has not completed successfully"}
	if job.StoredSummary != nil {
		for severity, count := range job.StoredSummary.Counts {
			s.Counts[severity] = count
		}
	}
	for _, f := range job.Findings {
		s.Counts[f.Severity]++
	}
	if job.Status == "failed" {
		s.Gate = "error"
		s.Reason = "scanner failure; no release approval"
	}
	if job.Status == "succeeded" {
		s.Gate = "pass"
		s.Reason = "no HIGH or CRITICAL findings under the configured V1 policy"
		if s.Counts["HIGH"]+s.Counts["CRITICAL"] > 0 {
			s.Gate = "block"
			s.Reason = "HIGH or CRITICAL findings require remediation"
		}
		if s.Counts["UNKNOWN"] > 0 {
			s.Gate = "error"
			s.Reason = "unknown finding severity; no release approval"
		}
		if job.Request.Kind == "trivy_report" && s.Gate == "pass" {
			s.Gate = "error"
			s.Reason = "imported report is not independently verified release evidence"
		}
	}
	return s
}

var imagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)

func Validate(r Request) error {
	if len(r.Target) == 0 || len(r.Target) > 255 {
		return errors.New("target must contain 1 to 255 bytes")
	}
	switch r.Kind {
	case "image":
		if !imagePattern.MatchString(r.Target) {
			return errors.New("invalid image reference")
		}
		if len(r.Manifest) > 0 || len(r.Report) > 0 {
			return errors.New("image scan does not accept manifest or report")
		}
	case "manifest":
		if len(r.Report) > 0 {
			return errors.New("manifest scan does not accept report")
		}
		if _, err := PolicyInput(r.Manifest); err != nil {
			return err
		}
	case "trivy_report":
		if len(r.Manifest) > 0 || len(r.Report) == 0 {
			return errors.New("report is required and manifest is not accepted")
		}
		if _, err := NormalizeTrivy(r.Report); err != nil {
			return err
		}
	default:
		return errors.New("kind must be image, manifest or trivy_report")
	}
	return nil
}
func RequestHash(r Request) string {
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func NormalizeFindings(items []Finding) []Finding {
	out := make([]Finding, 0, len(items))
	seen := map[string]bool{}
	for _, f := range items {
		f.Severity = strings.ToUpper(f.Severity)
		switch f.Severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
		default:
			f.Severity = "UNKNOWN"
		}
		raw, _ := json.Marshal([]string{f.RuleID, f.Resource, f.Package, f.InstalledVersion, f.FixedVersion})
		sum := sha256.Sum256(raw)
		f.Fingerprint = fmt.Sprintf("%x", sum[:16])
		if !seen[f.Fingerprint] {
			seen[f.Fingerprint] = true
			out = append(out, f)
		}
	}
	return out
}

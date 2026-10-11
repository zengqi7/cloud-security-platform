package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrState = errors.New("resource is not in the required state")

type WaiverRequest struct {
	ScanID      string    `json:"scan_id"`
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type Waiver struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	WaiverRequest
	RequestedBy    string     `json:"requested_by"`
	State          string     `json:"state"`
	DecidedBy      string     `json:"decided_by"`
	DecisionReason string     `json:"decision_reason"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
}
type WaiverDecision struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}
type Assessment struct {
	Trust          *TrustPolicy  `json:"trust_policy,omitempty"`
	Evidence       *ScanEvidence `json:"evidence,omitempty"`
	ID             string        `json:"id"`
	ScanID         string        `json:"scan_id"`
	PolicyDigest   string        `json:"policy_digest"`
	EvidenceSource string        `json:"evidence_source"`
	EvaluatedAt    time.Time     `json:"evaluated_at"`
	ValidUntil     time.Time     `json:"valid_until"`
	Subject        string        `json:"subject"`
	Original       Summary       `json:"original"`
	Effective      Summary       `json:"effective"`
	AppliedWaivers []Waiver      `json:"applied_waivers"`
}

func governancePrincipal(ctx context.Context, scope string) (auth.Principal, error) {
	p, ok := auth.FromContext(ctx)
	if !ok || !p.Allows(scope) {
		return p, auth.ErrUnauthorized
	}
	return p, nil
}
func (s Store) governanceTx(ctx context.Context, p auth.Principal) (*sql.Tx, time.Time, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	fail := func(err error) (*sql.Tx, time.Time, error) { tx.Rollback(); return nil, time.Time{}, err }
	// The no-op duplicate update takes an exclusive lock directly; INSERT IGNORE
	// followed by FOR UPDATE can deadlock when concurrent duplicate inserts upgrade.
	if _, err := tx.ExecContext(ctx, `INSERT INTO governance_locks(tenant) VALUES(?) ON DUPLICATE KEY UPDATE tenant=governance_locks.tenant`, p.Tenant); err != nil {
		return fail(err)
	}
	var tenant string
	if err := tx.QueryRowContext(ctx, `SELECT tenant FROM governance_locks WHERE tenant=? FOR UPDATE`, p.Tenant).Scan(&tenant); err != nil {
		return fail(err)
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(3)`).Scan(&now); err != nil {
		return fail(err)
	}
	return tx, now, nil
}
func validReason(reason string) bool { return strings.TrimSpace(reason) != "" && len(reason) <= 1024 }
func (s Store) RequestWaiver(ctx context.Context, r WaiverRequest) (Waiver, error) {
	p, err := governancePrincipal(ctx, "waivers:request")
	if err != nil {
		return Waiver{}, err
	}
	if !scanID.MatchString(r.ScanID) || len(r.Fingerprint) != 32 || !validReason(r.Reason) {
		return Waiver{}, ErrInvalid
	}
	tx, now, err := s.governanceTx(ctx, p)
	if err != nil {
		return Waiver{}, err
	}
	defer tx.Rollback()
	if !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(30*24*time.Hour)) {
		return Waiver{}, ErrInvalid
	}
	var severity, status string
	err = tx.QueryRowContext(ctx, `SELECT f.severity,j.status FROM scan_findings f JOIN scan_jobs j ON j.id=f.scan_id WHERE j.tenant=? AND j.id=? AND f.fingerprint=?`, p.Tenant, r.ScanID, r.Fingerprint).Scan(&severity, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return Waiver{}, ErrNotFound
	}
	if err != nil {
		return Waiver{}, err
	}
	if severity == "UNKNOWN" || status != "succeeded" {
		return Waiver{}, ErrState
	}
	w := Waiver{ID: NewID(), Tenant: p.Tenant, WaiverRequest: r, RequestedBy: p.Subject, State: "pending"}
	w.ExpiresAt = w.ExpiresAt.UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_waivers(id,tenant,scan_id,fingerprint,requested_by,reason,expires_at) VALUES(?,?,?,?,?,?,?)`, w.ID, p.Tenant, r.ScanID, r.Fingerprint, p.Subject, r.Reason, w.ExpiresAt); err != nil {
		return Waiver{}, err
	}
	if err := auditTx(ctx, tx, p, "waiver:request", w.ID); err != nil {
		return Waiver{}, err
	}
	return w, tx.Commit()
}

const selectWaiver = `SELECT id,tenant,scan_id,fingerprint,reason,expires_at,requested_by,state,COALESCE(decided_by,''),COALESCE(decision_reason,''),decided_at FROM finding_waivers `

func scanWaiver(row rowScanner) (Waiver, error) {
	var w Waiver
	err := row.Scan(&w.ID, &w.Tenant, &w.ScanID, &w.Fingerprint, &w.Reason, &w.ExpiresAt, &w.RequestedBy, &w.State, &w.DecidedBy, &w.DecisionReason, &w.DecidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	return w, err
}
func (s Store) GetWaiver(ctx context.Context, tenant, id string) (Waiver, error) {
	return scanWaiver(s.DB.QueryRowContext(ctx, selectWaiver+`WHERE tenant=? AND id=?`, tenant, id))
}
func (s Store) DecideWaiver(ctx context.Context, id string, d WaiverDecision) (Waiver, error) {
	p, err := governancePrincipal(ctx, "waivers:approve")
	if err != nil {
		return Waiver{}, err
	}
	if !scanID.MatchString(id) || !validReason(d.Reason) {
		return Waiver{}, ErrInvalid
	}
	expected, next := "pending", ""
	switch d.Action {
	case "approve":
		next = "approved"
	case "reject":
		next = "rejected"
	case "revoke":
		expected = "approved"
		next = "revoked"
	default:
		return Waiver{}, ErrInvalid
	}
	tx, now, err := s.governanceTx(ctx, p)
	if err != nil {
		return Waiver{}, err
	}
	defer tx.Rollback()
	w, err := scanWaiver(tx.QueryRowContext(ctx, selectWaiver+`WHERE tenant=? AND id=? FOR UPDATE`, p.Tenant, id))
	if err != nil {
		return w, err
	}
	if w.State != expected || !w.ExpiresAt.After(now) {
		return w, ErrState
	}
	if d.Action == "approve" && strings.EqualFold(w.RequestedBy, p.Subject) {
		return w, auth.ErrUnauthorized
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_waivers SET state=?,decided_by=?,decision_reason=?,decided_at=? WHERE id=?`, next, p.Subject, d.Reason, now, id); err != nil {
		return w, err
	}
	if err := auditTx(ctx, tx, p, "waiver:"+d.Action, id); err != nil {
		return w, err
	}
	w.State = next
	w.DecidedBy = p.Subject
	w.DecisionReason = d.Reason
	w.DecidedAt = &now
	return w, tx.Commit()
}
func (s Store) Assess(ctx context.Context, id, key string) (Assessment, error) {
	p, err := governancePrincipal(ctx, "assessments:write")
	if err != nil {
		return Assessment{}, err
	}
	if !scanID.MatchString(id) || strings.TrimSpace(key) == "" || len(key) > 128 {
		return Assessment{}, ErrInvalid
	}
	tx, now, err := s.governanceTx(ctx, p)
	if err != nil {
		return Assessment{}, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT assessment_json FROM gate_assessments WHERE tenant=? AND idempotency_key=?`, p.Tenant, key).Scan(&raw)
	if err == nil {
		var existing Assessment
		if err := json.Unmarshal(raw, &existing); err != nil {
			return existing, err
		}
		if existing.ScanID != id {
			return existing, ErrConflict
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Assessment{}, err
	}
	job, err := scanJob(tx.QueryRowContext(ctx, selectJob+`WHERE tenant=? AND id=? FOR SHARE`, p.Tenant, id))
	if err != nil {
		return Assessment{}, err
	}
	if job.Status != "succeeded" && job.Status != "failed" {
		return Assessment{}, ErrState
	}
	if digestPattern.MatchString(job.PolicyDigest) {
		var encoded []byte
		if err := tx.QueryRowContext(ctx, `SELECT bundle_json FROM policy_bundles WHERE tenant=? AND digest=?`, p.Tenant, job.PolicyDigest).Scan(&encoded); err != nil {
			return Assessment{}, err
		}
		job.Policy = &PolicyBundle{}
		if err := json.Unmarshal(encoded, job.Policy); err != nil {
			return Assessment{}, err
		}
		if job.Policy.Digest() != job.PolicyDigest {
			return Assessment{}, errors.New("policy digest mismatch")
		}
	}
	a := Assessment{Trust: job.Trust, ID: NewID(), ScanID: id, PolicyDigest: job.PolicyDigest, EvidenceSource: job.EvidenceSource, Evidence: job.Evidence, Subject: p.Subject, EvaluatedAt: now, ValidUntil: now.Add(15 * time.Minute), Original: summarizeAt(job, now), AppliedWaivers: []Waiver{}}
	if deadline, fresh := evidenceDeadline(job, now); fresh && !deadline.IsZero() && deadline.Before(a.ValidUntil) {
		a.ValidUntil = deadline
	}
	a.Effective = Summary{Counts: map[string]int{}, Gate: a.Original.Gate, Reason: a.Original.Reason}
	for severity, count := range a.Original.Counts {
		a.Effective.Counts[severity] = count
	}
	rows, err := tx.QueryContext(ctx, selectWaiver+`WHERE tenant=? AND scan_id=? AND state='approved' AND expires_at>? ORDER BY id`, p.Tenant, id, now)
	if err != nil {
		return Assessment{}, err
	}
	seen := map[string]bool{}
	for rows.Next() {
		w, err := scanWaiver(rows)
		if err != nil {
			rows.Close()
			return Assessment{}, err
		}
		if seen[w.Fingerprint] || a.Original.Gate == "error" {
			continue
		}
		seen[w.Fingerprint] = true
		a.AppliedWaivers = append(a.AppliedWaivers, w)
		if w.ExpiresAt.Before(a.ValidUntil) {
			a.ValidUntil = w.ExpiresAt
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Assessment{}, err
	}
	for _, w := range a.AppliedWaivers {
		var severity string
		if err := tx.QueryRowContext(ctx, `SELECT severity FROM scan_findings WHERE scan_id=? AND fingerprint=?`, id, w.Fingerprint).Scan(&severity); err != nil {
			return Assessment{}, err
		}
		a.Effective.Counts[severity]--
	}
	if a.Original.Gate != "error" && job.Policy != nil {
		effectiveJob := job
		effectiveJob.StoredSummary = &a.Effective
		effectiveJob.Findings = nil
		a.Effective = summarizeAt(effectiveJob, now)
		if len(a.AppliedWaivers) > 0 {
			a.Effective.Reason += "; approved time-limited waivers applied"
		}
	}
	raw, err = json.Marshal(a)
	if err != nil {
		return a, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gate_assessments(id,tenant,scan_id,idempotency_key,assessment_json,assessed_at) VALUES(?,?,?,?,?,?)`, a.ID, p.Tenant, id, key, raw, now); err != nil {
		return a, err
	}
	if err := auditTx(ctx, tx, p, "assessment:create", a.ID); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func (s Store) GetAssessment(ctx context.Context, tenant, id string) (Assessment, error) {
	var a Assessment
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT assessment_json FROM gate_assessments WHERE tenant=? AND id=?`, tenant, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(raw, &a)
	return a, err
}

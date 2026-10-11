package platform

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/migration"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mysqlerr "github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }

func NewID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(id[:])
}
func (s Store) Init(ctx context.Context) error {
	return migration.Apply(ctx, s.DB)
}
func (s Store) Submit(ctx context.Context, tenant, key string, r Request) (Job, bool, error) {
	id := NewID()
	if key == "" {
		key = id
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return Job{}, false, err
	}
	subject, source := "operator-direct", "worker-tool"
	p, authenticated := auth.FromContext(ctx)
	if authenticated {
		if p.Tenant != tenant || !p.Allows("scans:submit") || (r.Kind == "trivy_report" && !p.Allows("reports:import")) {
			return Job{}, false, auth.ErrUnauthorized
		}
		subject = p.Subject
	}
	if r.Kind == "trivy_report" {
		source = "ci-import-unverified"
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, false, err
	}
	defer tx.Rollback()
	policyDigest := r.PolicyDigest
	if policyDigest == "" {
		bundle := DefaultPolicy()
		policyDigest = bundle.Digest()
		encoded, _ := json.Marshal(bundle)
		if _, err := tx.ExecContext(ctx, `INSERT IGNORE INTO policy_bundles(tenant,digest,version,bundle_json,published_by) VALUES(?,?,?,?, 'builtin')`, tenant, policyDigest, bundle.Version, encoded); err != nil {
			return Job{}, false, err
		}
	}
	var policyCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_bundles WHERE tenant=? AND digest=?`, tenant, policyDigest).Scan(&policyCount); err != nil {
		return Job{}, false, err
	}
	if policyCount != 1 {
		return Job{}, false, ErrNotFound
	}
	asset, series, scope, err := registerAsset(ctx, tx, tenant, r, policyDigest)
	if err != nil {
		return Job{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_jobs(id,tenant,idempotency_key,request_hash,request_json,findings_json,submitted_by,evidence_source,policy_digest,asset_id,series_id,scope_hash) VALUES(?,?,?,?,?,JSON_ARRAY(),?,?,?,?,?,?)`, id, tenant, key, RequestHash(r), raw, subject, source, policyDigest, asset, series, scope)
	if err != nil {
		tx.Rollback()
		var duplicate *mysqlerr.MySQLError
		if !errors.As(err, &duplicate) || duplicate.Number != 1062 {
			return Job{}, false, err
		}
		var hash, existingID string
		if err := s.DB.QueryRowContext(ctx, "SELECT id,request_hash FROM scan_jobs WHERE tenant=? AND idempotency_key=?", tenant, key).Scan(&existingID, &hash); err != nil {
			return Job{}, false, err
		}
		if hash != RequestHash(r) {
			return Job{}, false, ErrConflict
		}
		job, err := s.Get(ctx, tenant, existingID)
		return job, true, err
	}
	if authenticated {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,?,?,'scan:submit',?,'succeeded')`, tenant, p.KeyID, p.Subject, id); err != nil {
			return Job{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Job{}, false, err
	}
	job, err := s.Get(ctx, tenant, id)
	return job, false, err
}

const selectJob = `SELECT id,tenant,status,request_json,attempts,COALESCE(error_text,''),summary_json,created_at,finished_at,COALESCE(lease_token,''),submitted_by,evidence_source,policy_digest,COALESCE(asset_id,''),COALESCE(series_id,''),scope_hash,evidence_json FROM scan_jobs `

type rowScanner interface{ Scan(...any) error }

func scanJob(row rowScanner) (Job, error) {
	var j Job
	var request, summary, evidence []byte
	err := row.Scan(&j.ID, &j.Tenant, &j.Status, &request, &j.Attempts, &j.Error, &summary, &j.CreatedAt, &j.FinishedAt, &j.LeaseToken, &j.SubmittedBy, &j.EvidenceSource, &j.PolicyDigest, &j.AssetID, &j.SeriesID, &j.ScopeHash, &evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal(request, &j.Request); err != nil {
		return Job{}, err
	}
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &j.Evidence); err != nil {
			return Job{}, err
		}
	}
	if len(summary) > 0 {
		j.StoredSummary = &Summary{}
		if err := json.Unmarshal(summary, j.StoredSummary); err != nil {
			return Job{}, err
		}
	}
	return j, nil
}
func (s Store) Get(ctx context.Context, tenant, id string) (Job, error) {
	j, err := scanJob(s.DB.QueryRowContext(ctx, selectJob+"WHERE tenant=? AND id=?", tenant, id))
	if err != nil {
		return j, err
	}
	if digestPattern.MatchString(j.PolicyDigest) {
		b, err := s.LoadPolicy(ctx, tenant, j.PolicyDigest)
		if err != nil {
			return j, err
		}
		j.Policy = &b
	}
	return j, nil
}
func (s Store) List(ctx context.Context, tenant string, limit int) ([]Job, error) {
	rows, err := s.DB.QueryContext(ctx, selectJob+"WHERE tenant=? ORDER BY created_at DESC,id DESC LIMIT ?", tenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := make([]Job, 0)
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range jobs {
		if digestPattern.MatchString(jobs[i].PolicyDigest) {
			b, err := s.LoadPolicy(ctx, tenant, jobs[i].PolicyDigest)
			if err != nil {
				return nil, err
			}
			jobs[i].Policy = &b
		}
	}
	return jobs, nil
}
func (s Store) Claim(ctx context.Context) (Job, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	// Terminate jobs that repeatedly crash while holding a lease.
	_, err = tx.ExecContext(ctx, `UPDATE scan_jobs SET status='failed',error_text='worker lease expired after maximum attempts',finished_at=UTC_TIMESTAMP(3),lease_token=NULL,lease_until=NULL WHERE status='running' AND lease_until<=UTC_TIMESTAMP(3) AND attempts>=3`)
	if err != nil {
		return Job{}, err
	}
	job, err := scanJob(tx.QueryRowContext(ctx, selectJob+`WHERE attempts<3 AND ((status='queued' AND next_attempt_at<=UTC_TIMESTAMP(3)) OR (status='running' AND lease_until<=UTC_TIMESTAMP(3))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`))
	if errors.Is(err, ErrNotFound) {
		if err := tx.Commit(); err != nil {
			return Job{}, err
		}
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	job.LeaseToken = NewID()
	job.Attempts++
	job.Status = "running"
	if _, err := tx.ExecContext(ctx, `UPDATE scan_jobs SET status='running',attempts=attempts+1,lease_token=?,lease_until=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 180 SECOND) WHERE id=?`, job.LeaseToken, job.ID); err != nil {
		return Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	return job, nil
}
func (s Store) Finish(ctx context.Context, job Job, findings []Finding, scanErr error) error {
	return s.FinishEvidence(ctx, job, ScanResult{Findings: findings}, scanErr)
}
func (s Store) FinishEvidence(ctx context.Context, job Job, result ScanResult, scanErr error) error {
	findings := result.Findings
	status := "succeeded"
	message := ""
	if scanErr != nil {
		status = "failed"
		message = scanErr.Error()
		if job.Attempts < 3 {
			status = "queued"
		}
	}
	if findings == nil {
		findings = []Finding{}
	}
	findings = NormalizeFindings(findings)
	summaryJob := Job{Status: status, Findings: findings, Request: job.Request}
	raw, err := json.Marshal(Summarize(summaryJob))
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	evidence, err := json.Marshal(result.Evidence)
	if err != nil {
		return err
	}
	var sbom any
	if len(result.SBOM) > 0 {
		sbom = []byte(result.SBOM)
	}
	settled, err := tx.ExecContext(ctx, `UPDATE scan_jobs SET status=?,error_text=?,summary_json=?,evidence_json=?,sbom_json=?,lease_token=NULL,lease_until=NULL,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 15 SECOND),finished_at=IF(?='queued',NULL,UTC_TIMESTAMP(3)) WHERE id=? AND tenant=? AND status='running' AND lease_token=? AND lease_until>UTC_TIMESTAMP(3)`, status, message, raw, evidence, sbom, status, job.ID, job.Tenant, job.LeaseToken)
	if err != nil {
		return err
	}
	n, err := settled.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	if scanErr == nil {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO scan_findings(scan_id,fingerprint,severity,finding_json) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, f := range findings {
			raw, err := json.Marshal(f)
			if err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, job.ID, f.Fingerprint, f.Severity, raw); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func (s Store) Ping(ctx context.Context) error { return s.DB.PingContext(ctx) }
func OpenStore(dsn string) (Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return Store{}, err
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	s := Store{DB: db}
	if err := waitForMySQL(s, 60*time.Second); err != nil {
		db.Close()
		return Store{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Verify(ctx, db); err != nil {
		db.Close()
		return Store{}, err
	}
	return s, nil
}

func waitForMySQL(store Store, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		lastErr = store.Ping(ctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("mysql not ready after %s: %w", timeout, lastErr)
}

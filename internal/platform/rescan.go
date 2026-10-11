package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type RescanRequest struct {
	ScanID          string `json:"scan_id"`
	IntervalSeconds int    `json:"interval_seconds"`
}
type RescanSchedule struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	RescanRequest
	NextRunAt time.Time `json:"next_run_at"`
	Enabled   bool      `json:"enabled"`
	Subject   string    `json:"subject"`
}

func (s Store) CreateRescan(ctx context.Context, r RescanRequest) (RescanSchedule, error) {
	p, err := governancePrincipal(ctx, "rescans:write")
	if err != nil {
		return RescanSchedule{}, err
	}
	if !p.Allows("scans:submit") {
		return RescanSchedule{}, auth.ErrUnauthorized
	}
	if !scanID.MatchString(r.ScanID) || r.IntervalSeconds < 3600 || r.IntervalSeconds > 30*86400 {
		return RescanSchedule{}, ErrInvalid
	}
	tx, now, err := s.governanceTx(ctx, p)
	if err != nil {
		return RescanSchedule{}, err
	}
	defer tx.Rollback()
	job, err := scanJob(tx.QueryRowContext(ctx, selectJob+`WHERE tenant=? AND id=? FOR SHARE`, p.Tenant, r.ScanID))
	if err != nil {
		return RescanSchedule{}, err
	}
	if job.Status != "succeeded" || (job.Request.Kind != "image" && job.Request.Kind != "manifest") {
		return RescanSchedule{}, ErrState
	}
	if job.Request.Kind == "image" && !imageDigest.MatchString(job.Request.Target) {
		return RescanSchedule{}, ErrInvalid
	}
	request := job.Request
	request.PolicyDigest = job.PolicyDigest
	if request.Asset == "" {
		request.Asset = request.Target
	}
	if request.Series == "" {
		request.Series = "default"
	}
	trust, err := loadTrustPolicy()
	if err != nil {
		return RescanSchedule{}, err
	}
	raw, _ := json.Marshal(request)
	traw, _ := json.Marshal(trust)
	schedule := RescanSchedule{ID: NewID(), Tenant: p.Tenant, RescanRequest: r, NextRunAt: now.Add(time.Duration(r.IntervalSeconds) * time.Second), Enabled: true, Subject: p.Subject}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rescan_schedules(id,tenant,source_scan_id,request_json,trust_json,interval_seconds,next_run_at,key_id,subject) VALUES(?,?,?,?,?,?,?,?,?)`, schedule.ID, p.Tenant, r.ScanID, raw, traw, r.IntervalSeconds, schedule.NextRunAt, p.KeyID, p.Subject); err != nil {
		return RescanSchedule{}, err
	}
	if err := auditTx(ctx, tx, p, "rescan:create", schedule.ID); err != nil {
		return RescanSchedule{}, err
	}
	return schedule, tx.Commit()
}
func (s Store) GetRescan(ctx context.Context, tenant, id string) (RescanSchedule, error) {
	var r RescanSchedule
	err := s.DB.QueryRowContext(ctx, `SELECT id,tenant,source_scan_id,interval_seconds,next_run_at,enabled,subject FROM rescan_schedules WHERE tenant=? AND id=?`, tenant, id).Scan(&r.ID, &r.Tenant, &r.ScanID, &r.IntervalSeconds, &r.NextRunAt, &r.Enabled, &r.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}
func (s Store) DisableRescan(ctx context.Context, id, reason string) error {
	p, err := governancePrincipal(ctx, "rescans:write")
	if err != nil {
		return err
	}
	if !scanID.MatchString(id) || !validReason(reason) {
		return ErrInvalid
	}
	tx, _, err := s.governanceTx(ctx, p)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var found string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM rescan_schedules WHERE tenant=? AND id=? FOR UPDATE`, p.Tenant, id).Scan(&found); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rescan_schedules SET enabled=FALSE,disable_reason=? WHERE id=?`, reason, id); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, p, "rescan:disable", id); err != nil {
		return err
	}
	return tx.Commit()
}

// A due period and its new job commit together. Missed periods coalesce into one
// rescan; no unbounded catch-up burst after a long outage.
func (s Store) EnqueueRescan(ctx context.Context) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var r RescanSchedule
	var requestRaw, trustRaw []byte
	var keyID uint64
	err = tx.QueryRowContext(ctx, `SELECT id,tenant,source_scan_id,interval_seconds,next_run_at,subject,key_id,request_json,trust_json FROM rescan_schedules WHERE enabled=TRUE AND next_run_at<=UTC_TIMESTAMP(3) ORDER BY next_run_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&r.ID, &r.Tenant, &r.ScanID, &r.IntervalSeconds, &r.NextRunAt, &r.Subject, &keyID, &requestRaw, &trustRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var scopesRaw []byte
	var subject string
	err = tx.QueryRowContext(ctx, `SELECT subject,scopes_json FROM scan_api_keys WHERE id=? AND tenant=? AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(3) FOR SHARE`, keyID, r.Tenant).Scan(&subject, &scopesRaw)
	p := auth.Principal{KeyID: keyID, Tenant: r.Tenant, Subject: r.Subject}
	if err == nil {
		err = json.Unmarshal(scopesRaw, &p.Scopes)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if errors.Is(err, sql.ErrNoRows) || subject != r.Subject || !p.Allows("rescans:write") || !p.Allows("scans:submit") {
		if _, err := tx.ExecContext(ctx, `UPDATE rescan_schedules SET enabled=FALSE WHERE id=?`, r.ID); err != nil {
			return false, err
		}
		if err := auditTx(ctx, tx, p, "rescan:credential-disabled", r.ID); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	var request Request
	if err := json.Unmarshal(requestRaw, &request); err != nil {
		return false, err
	}
	asset, series, scope, err := registerAsset(ctx, tx, r.Tenant, request, request.PolicyDigest)
	if err != nil {
		return false, err
	}
	id := NewID()
	key := "rescan:" + r.ID + ":" + r.NextRunAt.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_jobs(id,tenant,idempotency_key,request_hash,request_json,findings_json,submitted_by,evidence_source,policy_digest,asset_id,series_id,scope_hash,trust_json) VALUES(?,?,?,?,?,JSON_ARRAY(),?,'worker-tool',?,?,?,?,?)`, id, r.Tenant, key, RequestHash(request), requestRaw, r.Subject, request.PolicyDigest, asset, series, scope, trustRaw); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rescan_schedules SET next_run_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? SECOND) WHERE id=?`, r.IntervalSeconds, r.ID); err != nil {
		return false, err
	}
	if err := auditTx(ctx, tx, p, "rescan:enqueue", id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

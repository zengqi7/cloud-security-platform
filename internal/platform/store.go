package platform

import (
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
	_, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS scan_jobs (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 idempotency_key VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL,
 request_hash CHAR(64) NOT NULL,
 request_json JSON NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'queued',
 attempts INT NOT NULL DEFAULT 0,
 error_text TEXT NULL,
 findings_json JSON NOT NULL,
 lease_token CHAR(32) NULL,
 lease_until DATETIME(3) NULL,
 next_attempt_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 finished_at DATETIME(3) NULL,
 UNIQUE KEY uk_tenant_idempotency(tenant,idempotency_key),
 KEY idx_scan_queue(status,next_attempt_at),
 KEY idx_scan_lease(status,lease_until)
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	return err
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
	_, err = s.DB.ExecContext(ctx, `INSERT INTO scan_jobs(id,tenant,idempotency_key,request_hash,request_json,findings_json) VALUES(?,?,?,?,?,JSON_ARRAY())`, id, tenant, key, RequestHash(r), raw)
	if err != nil {
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
	job, err := s.Get(ctx, tenant, id)
	return job, false, err
}

const selectJob = `SELECT id,tenant,status,request_json,attempts,COALESCE(error_text,''),findings_json,created_at,finished_at,COALESCE(lease_token,'') FROM scan_jobs `

type rowScanner interface{ Scan(...any) error }

func scanJob(row rowScanner) (Job, error) {
	var j Job
	var request, findings []byte
	err := row.Scan(&j.ID, &j.Tenant, &j.Status, &request, &j.Attempts, &j.Error, &findings, &j.CreatedAt, &j.FinishedAt, &j.LeaseToken)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal(request, &j.Request); err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal(findings, &j.Findings); err != nil {
		return Job{}, err
	}
	return j, nil
}
func (s Store) Get(ctx context.Context, tenant, id string) (Job, error) {
	return scanJob(s.DB.QueryRowContext(ctx, selectJob+"WHERE tenant=? AND id=?", tenant, id))
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
	return jobs, rows.Err()
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
	raw, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE scan_jobs SET status=?,error_text=?,findings_json=?,lease_token=NULL,lease_until=NULL,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 15 SECOND),finished_at=IF(?='queued',NULL,UTC_TIMESTAMP(3)) WHERE id=? AND tenant=? AND status='running' AND lease_token=?`, status, message, raw, status, job.ID, job.Tenant, job.LeaseToken)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return nil
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
	if err := s.Init(ctx); err != nil {
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

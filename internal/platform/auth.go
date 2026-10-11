package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func (s Store) Authenticate(ctx context.Context, token string) (auth.Principal, error) {
	var p auth.Principal
	if len(token) < 32 || len(token) > 128 {
		return p, auth.ErrUnauthorized
	}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT id,tenant,subject,scopes_json FROM scan_api_keys WHERE token_hash=? AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(3)`, auth.Hash(token)).Scan(&p.KeyID, &p.Tenant, &p.Subject, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, auth.ErrUnauthorized
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p.Scopes)
	return p, err
}
func (s Store) Audit(ctx context.Context, p auth.Principal, action, resource, outcome string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,?,?,?,?,?)`, p.Tenant, p.KeyID, p.Subject, action, resource, outcome)
	return err
}
func (s Store) CreateKey(ctx context.Context, tenant, subject string, scopes []string, expires time.Time) (uint64, string, error) {
	if err := auth.Validate(tenant, subject, scopes, expires); err != nil {
		return 0, "", err
	}
	token, err := auth.NewToken()
	if err != nil {
		return 0, "", err
	}
	raw, _ := json.Marshal(scopes)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO scan_api_keys(tenant,subject,token_hash,scopes_json,expires_at) VALUES(?,?,?,?,?)`, tenant, subject, auth.Hash(token), raw, expires.UTC())
	if err != nil {
		return 0, "", err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,?,?,'key:create','operator-cli','succeeded')`, tenant, id, subject); err != nil {
		return 0, "", err
	}
	if err := tx.Commit(); err != nil {
		return 0, "", err
	}
	return uint64(id), token, nil
}
func (s Store) RevokeKey(ctx context.Context, tenant string, id uint64, actor string) error {
	if actor == "" || len(actor) > 128 {
		return errors.New("operator actor required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE scan_api_keys SET revoked_at=UTC_TIMESTAMP(3) WHERE id=? AND tenant=? AND revoked_at IS NULL`, id, tenant)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return auth.ErrUnauthorized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,?,?,'key:revoke',?,'succeeded')`, tenant, id, actor, fmt.Sprintf("key:%d", id)); err != nil {
		return err
	}
	return tx.Commit()
}

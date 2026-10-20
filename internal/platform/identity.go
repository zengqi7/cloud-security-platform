package platform

import (
	"cloud-security-platform/internal/auth"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"
)

func RuntimeAuth(ctx context.Context, s Store) (auth.Repository, error) {
	issuer := os.Getenv("OIDC_ISSUER_URL")
	aud := os.Getenv("OIDC_AUDIENCE")
	if issuer == "" && aud == "" {
		return s, nil
	}
	return auth.NewOIDC(ctx, issuer, aud, s, s, nil)
}
func (s Store) ResolveOIDC(ctx context.Context, issuer, subject string) (auth.Principal, error) {
	var p auth.Principal
	var raw []byte
	var savedIssuer, savedSubject string
	err := s.DB.QueryRowContext(ctx, `SELECT issuer,oidc_subject,tenant,scopes_json FROM oidc_memberships WHERE issuer_hash=? AND subject_hash=? AND enabled=TRUE AND expires_at>UTC_TIMESTAMP(3)`, hashBytes([]byte(issuer)), hashBytes([]byte(subject))).Scan(&savedIssuer, &savedSubject, &p.Tenant, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, auth.ErrUnauthorized
	}
	if err != nil {
		return p, err
	}
	if savedIssuer != issuer || savedSubject != subject {
		return p, auth.ErrUnauthorized
	}
	p.Subject = "oidc:" + hashBytes([]byte(issuer+"\x00"+subject))
	if err := json.Unmarshal(raw, &p.Scopes); err != nil {
		return p, err
	}
	return p, nil
}

// Operator-only: no HTTP endpoint can provision or change tenant memberships.
func (s Store) SetOIDCMembership(ctx context.Context, issuer, subject, tenant, actor string, scopes []string, expires time.Time, enabled bool) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(issuer) > 512 || len(subject) > 512 || strings.TrimSpace(subject) == "" || strings.TrimSpace(actor) == "" || len(actor) > 128 {
		return ErrInvalid
	}
	if err := auth.Validate(tenant, subject, scopes, expires); err != nil {
		// Provider subjects can be longer than the API-key subject field.
		if len(subject) <= 128 {
			return err
		}
		if err := auth.Validate(tenant, "oidc-subject", scopes, expires); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(scopes)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO oidc_memberships(issuer_hash,subject_hash,issuer,oidc_subject,tenant,scopes_json,expires_at,enabled,updated_by) VALUES(?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE tenant=VALUES(tenant),scopes_json=VALUES(scopes_json),expires_at=VALUES(expires_at),enabled=VALUES(enabled),updated_by=VALUES(updated_by),updated_at=UTC_TIMESTAMP(3)`, hashBytes([]byte(issuer)), hashBytes([]byte(subject)), issuer, subject, tenant, raw, expires.UTC(), enabled, actor)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_audit_events(tenant,key_id,subject,action,resource,outcome) VALUES(?,NULL,?,'identity:configure',?,'succeeded')`, tenant, actor, "oidc:"+hashBytes([]byte(issuer+"\x00"+subject))); err != nil {
		return err
	}
	return tx.Commit()
}

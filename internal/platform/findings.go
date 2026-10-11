package platform

import (
	"context"
	"encoding/json"
	"errors"
)

type FindingRepository interface {
	Findings(context.Context, string, string, string, int, int) ([]Finding, int, error)
}

func (s Store) Findings(ctx context.Context, tenant, id, severity string, offset, limit int) ([]Finding, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, errors.New("invalid pagination")
	}
	// Tenant check prevents an empty page from hiding a foreign/nonexistent scan.
	if _, err := s.Get(ctx, tenant, id); err != nil {
		return nil, 0, err
	}
	where := ` FROM scan_findings f JOIN scan_jobs j ON j.id=f.scan_id WHERE j.tenant=? AND f.scan_id=?`
	args := []any{tenant, id}
	if severity != "" {
		where += ` AND f.severity=?`
		args = append(args, severity)
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*)`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, `SELECT f.finding_json`+where+` ORDER BY f.fingerprint LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Finding, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var f Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, 0, err
		}
		items = append(items, f)
	}
	return items, total, rows.Err()
}

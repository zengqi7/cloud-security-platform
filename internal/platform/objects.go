package platform

import (
	"cloud-security-platform/internal/blob"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type evidenceObject struct {
	Kind, Key, Digest string
	Size              int
}

// Reserve before upload. Unique attempt keys and a 24h GC quarantine prevent
// a late/crashed worker from deleting evidence linked by another lease.
func (s Store) archive(ctx context.Context, j Job, kind, digest string, raw []byte) (evidenceObject, error) {
	ref := evidenceObject{Kind: kind, Digest: digest, Size: len(raw)}
	if s.Objects == nil {
		return ref, nil
	}
	if !scanID.MatchString(j.ID) || !scanID.MatchString(j.LeaseToken) || len(raw) > blob.MaxSize {
		return ref, errors.New("invalid evidence archive identity or size")
	}
	if err := blob.Verify(raw, digest); err != nil {
		return ref, err
	}
	ref.Key = fmt.Sprintf("%s/%s/%s/%s/%s.json", hashBytes([]byte(j.Tenant)), j.ID, j.LeaseToken, kind, digest[7:])
	_, err := s.DB.ExecContext(ctx, `INSERT INTO evidence_objects(tenant,scan_id,lease_token,kind,object_key,digest,size_bytes) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE object_key=object_key`, j.Tenant, j.ID, j.LeaseToken, kind, ref.Key, digest, len(raw))
	if err != nil {
		return ref, err
	}
	var savedKey, savedDigest string
	var savedSize int
	if err := s.DB.QueryRowContext(ctx, `SELECT object_key,digest,size_bytes FROM evidence_objects WHERE tenant=? AND scan_id=? AND lease_token=? AND kind=?`, j.Tenant, j.ID, j.LeaseToken, kind).Scan(&savedKey, &savedDigest, &savedSize); err != nil {
		return ref, err
	}
	if savedKey != ref.Key || savedDigest != digest || savedSize != len(raw) {
		return ref, ErrState
	}
	if err := s.Objects.Put(ctx, ref.Key, raw); err != nil {
		return ref, err
	}
	return ref, nil
}
func (s Store) readObject(ctx context.Context, tenant, id, kind string) ([]byte, error) {
	var key, digest string
	var size int
	err := s.DB.QueryRowContext(ctx, `SELECT object_key,digest,size_bytes FROM evidence_objects WHERE tenant=? AND scan_id=? AND kind=? AND linked=TRUE`, tenant, id, kind).Scan(&key, &digest, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.Objects == nil {
		return nil, errors.New("evidence object store not configured")
	}
	raw, err := s.Objects.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, ErrState
	}
	if err := blob.Verify(raw, digest); err != nil {
		return nil, err
	}
	return raw, nil
}

// CollectOrphans only deletes unlinked objects after all worker leases have
// expired by many hours. Linked evidence never participates in automatic GC.
func (s Store) CollectOrphans(ctx context.Context, limit int) (int, error) {
	if s.Objects == nil || limit < 1 || limit > 1000 {
		return 0, errors.New("object store and GC limit 1..1000 required")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT e.object_key FROM evidence_objects e JOIN scan_jobs j ON j.id=e.scan_id WHERE e.linked=FALSE AND e.created_at<DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 24 HOUR) AND NOT(j.status='running' AND j.lease_token=e.lease_token AND j.lease_until>UTC_TIMESTAMP(3)) ORDER BY e.created_at LIMIT ?`, limit)
	if err != nil {
		return 0, err
	}
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return 0, err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for i, key := range keys {
		if err := s.Objects.Delete(ctx, key); err != nil {
			return i, err
		}
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM evidence_objects WHERE object_key=? AND linked=FALSE`, key); err != nil {
			return i, err
		}
	}
	return len(keys), nil
}

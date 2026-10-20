//go:build integration

package integration

import (
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type memoryObjects map[string][]byte

func (m memoryObjects) Put(_ context.Context, k string, v []byte) error {
	m[k] = append([]byte(nil), v...)
	return nil
}
func (m memoryObjects) Get(_ context.Context, k string) ([]byte, error) {
	v, ok := m[k]
	if !ok {
		return nil, errors.New("missing object")
	}
	return v, nil
}
func (m memoryObjects) Delete(_ context.Context, k string) error { delete(m, k); return nil }
func TestObjectSettlementIntegrityAndGC(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	objects := memoryObjects{}
	s := platform.Store{DB: db, Objects: objects}
	job, _, err := s.Submit(ctx, "objects", "first", platform.Request{Kind: "image", Target: "registry.example/app:1"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(ctx)
	if err != nil || claimed.ID != job.ID {
		t.Fatalf("claim: %v", err)
	}
	raw := json.RawMessage(`{"bomFormat":"CycloneDX"}`)
	result := platform.ScanResult{SBOM: raw, Evidence: &platform.ScanEvidence{Complete: true, SBOMDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}}
	if err := s.FinishEvidence(ctx, claimed, result, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SBOM(ctx, "other", job.ID); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("tenant isolation: %v", err)
	}
	if _, err := s.SBOM(ctx, "objects", job.ID); err != nil {
		t.Fatal(err)
	}
	for key := range objects {
		objects[key] = []byte(`{}`)
	}
	if _, err := s.SBOM(ctx, "objects", job.ID); err == nil {
		t.Fatal("object corruption fell back to SQL")
	}
	if _, err := db.ExecContext(ctx, `UPDATE evidence_objects SET created_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 48 HOUR)`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CollectOrphans(ctx, 100); err != nil || n != 0 {
		t.Fatalf("linked GC: %d %v", n, err)
	}
	// The same object becomes eligible only when explicitly unlinked (lost lease fixture).
	if _, err := db.ExecContext(ctx, `UPDATE evidence_objects SET linked=FALSE`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CollectOrphans(ctx, 100); err != nil || n != 1 || len(objects) != 0 {
		t.Fatalf("orphan GC: %d %v", n, err)
	}
}

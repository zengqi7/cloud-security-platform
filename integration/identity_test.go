//go:build integration

package integration

import (
	"cloud-security-platform/internal/auth"
	"cloud-security-platform/internal/migration"
	"cloud-security-platform/internal/platform"
	"context"
	"errors"
	"testing"
	"time"
)

func TestOIDCMembershipGovernanceAndRevocation(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	if err := migration.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := platform.Store{DB: db}
	scopes := []string{"scans:read", "scans:submit", "rescans:write"}
	expiry := time.Now().Add(time.Hour)
	if err := s.SetOIDCMembership(ctx, "https://issuer.example", "User-A", "tenant-one", "operator", scopes, expiry, true); err != nil {
		t.Fatal(err)
	}
	p, err := s.ResolveOIDC(ctx, "https://issuer.example", "User-A")
	if err != nil || p.Tenant != "tenant-one" || p.KeyID != 0 {
		t.Fatalf("principal: %+v %v", p, err)
	}
	if _, err := s.ResolveOIDC(ctx, "https://issuer.example", "user-a"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("case-insensitive subject match")
	}
	if _, err := s.CreateRescan(auth.WithPrincipal(ctx, p), platform.RescanRequest{}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("OIDC created API-key bound recurring schedule")
	}
	if err := s.SetOIDCMembership(ctx, "https://issuer.example", "User-A", "tenant-one", "operator", scopes, expiry, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveOIDC(ctx, "https://issuer.example", "User-A"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("revoked identity accepted")
	}
}

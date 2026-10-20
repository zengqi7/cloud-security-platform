package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type identityFixture struct{ enabled bool }

func (f *identityFixture) ResolveOIDC(_ context.Context, issuer, subject string) (Principal, error) {
	if !f.enabled || subject != "user-1" {
		return Principal{}, ErrUnauthorized
	}
	return Principal{Tenant: "server-tenant", Subject: issuer + subject, Scopes: []string{"scans:read"}}, nil
}
func (f *identityFixture) Authenticate(context.Context, string) (Principal, error) {
	return Principal{Tenant: "api-key"}, nil
}
func (f *identityFixture) Audit(context.Context, Principal, string, string, string) error { return nil }
func TestOIDCAccessTokenAndJWKSRotation(t *testing.T) {
	first, _ := rsa.GenerateKey(rand.Reader, 2048)
	second, _ := rsa.GenerateKey(rand.Reader, 2048)
	var mu sync.Mutex
	active := first
	kid := "one"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &active.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	fixture := &identityFixture{enabled: true}
	o, err := NewOIDC(context.Background(), server.URL, "gate-api", fixture, fixture, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(key *rsa.PrivateKey, kid, typ, aud, issuer, subject string, expiry time.Time) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "aud": aud, "sub": subject, "exp": expiry.Unix(), "iat": time.Now().Unix(), "tenant": "attacker", "scope": "waivers:approve"})
		signed, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	valid := sign(first, "one", "at+jwt", "gate-api", server.URL, "user-1", time.Now().Add(time.Hour))
	p, err := o.Authenticate(context.Background(), valid)
	if err != nil || p.Tenant != "server-tenant" || p.Allows("waivers:approve") {
		t.Fatalf("trusted mapping: %+v %v", p, err)
	}
	for _, token := range []string{sign(first, "one", "JWT", "gate-api", server.URL, "user-1", time.Now().Add(time.Hour)), sign(first, "one", "at+jwt", "other-api", server.URL, "user-1", time.Now().Add(time.Hour)), sign(first, "one", "at+jwt", "gate-api", "https://other.example", "user-1", time.Now().Add(time.Hour)), sign(first, "one", "at+jwt", "gate-api", server.URL, "user-1", time.Now().Add(-time.Hour)), sign(first, "one", "at+jwt", "gate-api", server.URL, "unknown", time.Now().Add(time.Hour))} {
		if _, err := o.Authenticate(context.Background(), token); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
	mu.Lock()
	active = second
	kid = "two"
	mu.Unlock()
	if _, err := o.Authenticate(context.Background(), sign(second, "two", "at+jwt", "gate-api", server.URL, "user-1", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("JWKS rotation: %v", err)
	}
	fixture.enabled = false
	if _, err := o.Authenticate(context.Background(), valid); err == nil {
		t.Fatal("disabled membership accepted")
	}
	if p, err := o.Authenticate(context.Background(), "csp_fixture"); err != nil || p.Tenant != "api-key" {
		t.Fatal("API key fallback failed")
	}
}

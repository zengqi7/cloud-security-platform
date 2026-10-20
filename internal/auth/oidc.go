package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Membership interface {
	ResolveOIDC(context.Context, string, string) (Principal, error)
}
type OIDC struct {
	Keys     Repository
	Members  Membership
	verifier *oidc.IDTokenVerifier
	issuer   string
}

// Accept only RFC 9068 JWT access tokens, never an OIDC login ID token. The
// trusted issuer and audience are operator configuration, not token claims.
func NewOIDC(ctx context.Context, issuer, audience string, keys Repository, members Membership, client *http.Client) (*OIDC, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || audience == "" {
		return nil, errors.New("OIDC requires HTTPS issuer and API audience")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.New("OIDC discovery unavailable")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, errors.New("invalid OIDC metadata")
	}
	jwks, err := url.Parse(metadata.JWKS)
	if err != nil || jwks.Scheme != "https" || jwks.Host == "" || jwks.User != nil {
		return nil, errors.New("OIDC JWKS must use HTTPS")
	}
	return &OIDC{Keys: keys, Members: members, issuer: issuer, verifier: provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256", "ES256"}})}, nil
}
func (o *OIDC) Authenticate(ctx context.Context, token string) (Principal, error) {
	if strings.HasPrefix(token, "csp_") {
		return o.Keys.Authenticate(ctx, token)
	}
	if len(token) > 16384 {
		return Principal{}, ErrUnauthorized
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	var header struct {
		Type string `json:"typ"`
	}
	if json.Unmarshal(raw, &header) != nil || (header.Type != "at+jwt" && header.Type != "application/at+jwt") {
		return Principal{}, ErrUnauthorized
	}
	verified, err := o.verifier.Verify(ctx, token)
	if err != nil || verified.Subject == "" || len(verified.Subject) > 512 {
		return Principal{}, ErrUnauthorized
	}
	var claims struct {
		NotBefore int64 `json:"nbf"`
	}
	if verified.Claims(&claims) != nil || claims.NotBefore > time.Now().Unix() {
		return Principal{}, ErrUnauthorized
	}
	return o.Members.ResolveOIDC(ctx, o.issuer, verified.Subject)
}
func (o *OIDC) Audit(ctx context.Context, p Principal, action, resource, outcome string) error {
	return o.Keys.Audit(ctx, p, action, resource, outcome)
}

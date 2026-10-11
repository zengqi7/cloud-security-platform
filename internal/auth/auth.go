package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

var ErrUnauthorized = errors.New("invalid or expired credential")

type Principal struct {
	KeyID           uint64
	Tenant, Subject string
	Scopes          []string
}

func (p Principal) Allows(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok
}

type Repository interface {
	Authenticate(context.Context, string) (Principal, error)
	Audit(context.Context, Principal, string, string, string) error
}

func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func NewToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "csp_" + hex.EncodeToString(raw[:]), nil
}

var tenantName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func Validate(tenant, subject string, scopes []string, expires time.Time) error {
	if !tenantName.MatchString(tenant) || strings.TrimSpace(subject) == "" || len(subject) > 128 || len(scopes) == 0 || !expires.After(time.Now()) {
		return errors.New("tenant,subject,scopes and future expiry required")
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		switch scope {
		case "scans:read", "scans:submit", "reports:import", "policies:publish", "waivers:request", "waivers:approve", "assessments:write", "inventory:write", "rescans:write":
		default:
			return errors.New("unknown scope")
		}
		if seen[scope] {
			return errors.New("duplicate scope")
		}
		seen[scope] = true
	}
	return nil
}

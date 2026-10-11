package auth

import (
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken()
	if err != nil || a == b || len(a) != 68 || Hash(a) == a {
		t.Fatal("invalid token generation", err)
	}
	if err := Validate("acme", "ci", []string{"scans:read", "scans:submit"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, scopes := range [][]string{nil, {"admin"}, {"scans:read", "scans:read"}} {
		if err := Validate("acme", "ci", scopes, time.Now().Add(time.Hour)); err == nil {
			t.Fatal("invalid scopes accepted")
		}
	}
	if err := Validate("acme", "ci", []string{"scans:read"}, time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("past expiry accepted")
	}
}

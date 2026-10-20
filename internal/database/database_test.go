package database

import "testing"

func TestTLSAndPoolPolicy(t *testing.T) {
	t.Setenv("MYSQL_REQUIRE_TLS", "true")
	t.Setenv("MYSQL_TLS_CA_FILE", "")
	for _, suffix := range []string{"", "?tls=skip-verify", "?tls=preferred", "?tls=false"} {
		if _, err := Config("app:secret@tcp(db.example:3306)/cloud" + suffix); err == nil {
			t.Fatalf("accepted insecure TLS: %s", suffix)
		}
	}
	c, err := Config("app:secret@tcp(db.example:3306)/cloud?tls=true")
	if err != nil || !c.ParseTime || c.Timeout == 0 {
		t.Fatalf("verified configuration: %v", err)
	}
	t.Setenv("DB_MAX_OPEN_CONNS", "2")
	t.Setenv("DB_MAX_IDLE_CONNS", "3")
	if db, err := Open("app:secret@tcp(db.example:3306)/cloud?tls=true"); err == nil {
		db.Close()
		t.Fatal("idle exceeds pool budget")
	}
}

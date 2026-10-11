package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed sql/*.sql
var scripts embed.FS

func Files() ([]string, error) {
	names, err := fs.Glob(scripts, "sql/*.sql")
	sort.Strings(names)
	return names, err
}
func Apply(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked int
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK('cloudguard_migrations',10)`).Scan(&locked); err != nil || locked != 1 {
		return errors.New("cannot acquire migration lock")
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK('cloudguard_migrations')`)
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(name VARCHAR(255) PRIMARY KEY,checksum CHAR(64) NOT NULL,dirty BOOLEAN NOT NULL,applied_at DATETIME(3) NULL)`); err != nil {
		return err
	}
	names, err := Files()
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := scripts.ReadFile(name)
		if err != nil {
			return err
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(raw))
		var stored string
		var dirty bool
		err = conn.QueryRowContext(ctx, `SELECT checksum,dirty FROM schema_migrations WHERE name=?`, name).Scan(&stored, &dirty)
		if err == nil {
			if stored != hash || dirty {
				return fmt.Errorf("migration %s checksum mismatch or dirty: inspect/restore before retry", name)
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations(name,checksum,dirty) VALUES(?,?,TRUE)`, name, hash); err != nil {
			return err
		}
		for i, stmt := range Statements(string(raw)) {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration %s statement %d: %w; nontransactional DDL, inspect dirty schema", name, i+1, err)
			}
		}
		if _, err := conn.ExecContext(ctx, `UPDATE schema_migrations SET dirty=FALSE,applied_at=UTC_TIMESTAMP(3) WHERE name=?`, name); err != nil {
			return err
		}
	}
	return nil
}

// Embedded migrations use simple statements, with no semicolons inside literals.
func Statements(raw string) []string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	var out []string
	for _, stmt := range strings.Split(strings.Join(lines, "\n"), ";") {
		if strings.TrimSpace(stmt) != "" {
			out = append(out, strings.TrimSpace(stmt))
		}
	}
	return out
}
func Verify(ctx context.Context, db *sql.DB) error {
	names, err := Files()
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := scripts.ReadFile(name)
		if err != nil {
			return err
		}
		var stored string
		var dirty bool
		if err := db.QueryRowContext(ctx, `SELECT checksum,dirty FROM schema_migrations WHERE name=?`, name).Scan(&stored, &dirty); err != nil {
			return fmt.Errorf("run cmd/migrate before startup: %w", err)
		}
		if dirty || stored != fmt.Sprintf("%x", sha256.Sum256(raw)) {
			return fmt.Errorf("migration %s dirty or mismatched", name)
		}
	}
	return nil
}

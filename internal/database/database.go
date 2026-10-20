// Package database configures the same TLS and pool policy for every SQL binary.
package database

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"
)

func Config(dsn string) (*mysql.Config, error) {
	c, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, errors.New("invalid MySQL DSN")
	}
	require := os.Getenv("MYSQL_REQUIRE_TLS")
	if require != "" && require != "true" && require != "false" {
		return nil, errors.New("MYSQL_REQUIRE_TLS must be true or false")
	}
	if ca := os.Getenv("MYSQL_TLS_CA_FILE"); ca != "" {
		raw, err := os.ReadFile(ca)
		if err != nil {
			return nil, errors.New("MySQL CA file unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("invalid MySQL CA PEM")
		}
		name := fmt.Sprintf("cloudguard-%x", sha256.Sum256(raw))
		if err := mysql.RegisterTLSConfig(name, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}); err != nil {
			return nil, errors.New("cannot register MySQL TLS configuration")
		}
		c.TLSConfig = name
	}
	if require == "true" && (c.Net != "tcp" || c.TLSConfig == "" || c.TLSConfig == "false" || c.TLSConfig == "skip-verify" || c.TLSConfig == "preferred") {
		return nil, errors.New("MySQL requires verified TCP TLS (tls=true or MYSQL_TLS_CA_FILE)")
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 30 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 30 * time.Second
	}
	c.ParseTime = true
	return c, nil
}

func Open(dsn string) (*sql.DB, error) {
	c, err := Config(dsn)
	if err != nil {
		return nil, err
	}
	max, err := number("DB_MAX_OPEN_CONNS", 12, 1, 512)
	if err != nil {
		return nil, err
	}
	idle, err := number("DB_MAX_IDLE_CONNS", 4, 0, max)
	if err != nil {
		return nil, err
	}
	lifetime := 5 * time.Minute
	if v := os.Getenv("DB_CONN_MAX_LIFETIME"); v != "" {
		lifetime, err = time.ParseDuration(v)
		if err != nil || lifetime < time.Second || lifetime > time.Hour {
			return nil, errors.New("DB_CONN_MAX_LIFETIME must be between 1s and 1h")
		}
	}
	connector, err := mysql.NewConnector(c)
	if err != nil {
		return nil, errors.New("invalid MySQL connector configuration")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(max)
	db.SetMaxIdleConns(idle)
	db.SetConnMaxLifetime(lifetime)
	db.SetConnMaxIdleTime(time.Minute)
	return db, nil
}
func number(name string, fallback, min, max int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return n, nil
}

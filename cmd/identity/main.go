package main

import (
	"cloud-security-platform/internal/platform"
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	issuer := flag.String("issuer", "", "trusted HTTPS issuer")
	subject := flag.String("subject", "", "provider subject")
	tenant := flag.String("tenant", "", "server-owned tenant")
	actor := flag.String("actor", "", "operator audit identity")
	scopes := flag.String("scopes", "scans:read", "explicit scopes")
	ttl := flag.Duration("ttl", 24*time.Hour, "membership expiry")
	enabled := flag.Bool("enabled", true, "enable membership (false revokes)")
	flag.Parse()
	s, err := platform.OpenStore(os.Getenv("MYSQL_DSN"))
	if err != nil {
		log.Fatal(err)
	}
	defer s.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.SetOIDCMembership(ctx, *issuer, *subject, *tenant, *actor, strings.Split(*scopes, ","), time.Now().Add(*ttl), *enabled); err != nil {
		log.Fatal(err)
	}
	log.Print("OIDC membership updated and audited")
}

package main

import (
	"cloud-security-platform/internal/platform"
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	action := flag.String("action", "create", "create or revoke")
	tenant := flag.String("tenant", "", "tenant")
	subject := flag.String("subject", "", "credential subject or revocation actor")
	scopes := flag.String("scopes", "scans:read,scans:submit", "comma separated scopes")
	ttl := flag.Duration("ttl", 24*time.Hour, "credential lifetime")
	id := flag.Uint64("id", 0, "key ID to revoke")
	flag.Parse()
	store, err := platform.OpenStore(os.Getenv("MYSQL_DSN"))
	if err != nil {
		log.Fatal("storage not ready; run migrations")
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch *action {
	case "create":
		id, token, err := store.CreateKey(ctx, *tenant, *subject, strings.Split(*scopes, ","), time.Now().Add(*ttl))
		if err != nil {
			log.Fatal(err)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"key_id": id, "token": token})
	case "revoke":
		if err := store.RevokeKey(ctx, *tenant, *id, *subject); err != nil {
			log.Fatal(err)
		}
		log.Print("credential revoked")
	default:
		log.Fatal("unknown action")
	}
}

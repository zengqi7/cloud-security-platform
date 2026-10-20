package main

import (
	"cloud-security-platform/internal/platform"
	"context"
	"log"
	"os"
	"time"
)

func main() {
	store, err := platform.OpenStore(os.Getenv("MYSQL_DSN"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := store.CollectOrphans(ctx, 100)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("unlinked objects collected=%d", n)
}

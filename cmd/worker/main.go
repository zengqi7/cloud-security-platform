package main

import (
	"cloud-security-platform/internal/platform"
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		log.Fatal("MYSQL_DSN is required")
	}
	store, err := platform.OpenStore(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()
	data := os.Getenv("SCAN_DATA_DIR")
	if data == "" {
		data = "data"
	}
	scanner, err := platform.NewToolScanner(data)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Print("cloud-security worker started")
	if err := (platform.Worker{Repo: store, Scanner: scanner}).Run(ctx); err != nil {
		log.Fatal(err)
	}
}

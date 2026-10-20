package main

import (
	"cloud-security-platform/internal/platform"
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	health := &platform.WorkerHealth{}
	addr := os.Getenv("WORKER_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8083"
	}
	server := &http.Server{Addr: addr, Handler: health.Handler(store), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("worker health server failed: %v", err)
			stop()
		}
	}()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	log.Print("cloud-security worker started")
	if err := (platform.Worker{Repo: store, Scanner: scanner, Health: health}).Run(ctx); err != nil {
		log.Fatal(err)
	}
}

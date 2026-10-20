package main

import (
	"cloud-security-platform/internal/database"
	"cloud-security-platform/internal/migration"
	"context"
	"log"
	"os"
	"time"
)

func main() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		log.Fatal("MYSQL_DSN required")
	}
	db, err := database.Open(dsn)
	if err != nil {
		log.Fatal("database open failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := migration.Apply(ctx, db); err != nil {
		log.Fatal(err)
	}
	log.Print("migrations verified and applied")
}

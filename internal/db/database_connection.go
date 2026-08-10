package database

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

const (
	connectRetries = 10
	connectBackoff = 2 * time.Second
)

func Connect(ctx context.Context) error {
	// Pull from ENV variable for database URL
	connString := os.Getenv("DATABASE_URL")

	var pool *pgxpool.Pool
	var err error

	for attempt := 1; attempt <= connectRetries; attempt++ {
		pool, err = pgxpool.New(ctx, connString)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				Pool = pool
				return nil
			}
			pool.Close()
		}

		if attempt < connectRetries {
			time.Sleep(connectBackoff)
		}
	}

	return fmt.Errorf("unable to connect to database after %d attempts: %w", connectRetries, err)
}

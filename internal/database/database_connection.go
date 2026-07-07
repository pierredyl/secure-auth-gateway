package database

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func Connect(ctx context.Context) error {
	// Pull from ENV variable for database URL
	connString := os.Getenv("DATABASE_URL")

	// Establish the connection
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Ping the DB to check connection is valid
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("unable to ping database: %w", err)
	}

	Pool = pool
	return nil
}

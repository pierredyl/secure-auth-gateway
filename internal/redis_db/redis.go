package redis_db

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-chi/httprate"
	httprateredis "github.com/go-chi/httprate-redis"
	"github.com/redis/go-redis/v9"
)

var (
	LimitCounter httprate.LimitCounter
	// Client is shared with the login lockout in lockout.go rather than opening
	// a second connection to the same Redis.
	Client *redis.Client
)

const (
	connectRetries = 10
	connectBackoff = 2 * time.Second
)

func Connect(ctx context.Context) error {
	rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_URL")})

	var err error
	for attempt := 1; attempt <= connectRetries; attempt++ {
		if err = rdb.Ping(ctx).Err(); err == nil {
			break
		}
		if attempt < connectRetries {
			time.Sleep(connectBackoff)
		}
	}
	if err != nil {
		return fmt.Errorf("unable to ping redis after %d attempts: %w", connectRetries, err)
	}

	counter, err := httprateredis.NewRedisLimitCounter(&httprateredis.Config{Client: rdb})
	if err != nil {
		return fmt.Errorf("unable to create redis limit counter: %w", err)
	}

	LimitCounter = counter
	Client = rdb
	return nil
}

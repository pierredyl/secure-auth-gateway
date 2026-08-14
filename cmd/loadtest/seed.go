package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"secure-auth-gateway/internal/redis_db"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// The account set is fixed and deterministic on purpose: the harness must never
// grow the users table no matter how many times it runs.
const (
	accountCount = 5
	// 23 characters, clearing the min=15,max=72 validator on RegisterRequest.
	accountPassword = "LoadTest-Passw0rd-2026!"
)

type account struct {
	email    string
	password string
}

func accounts() []account {
	out := make([]account, accountCount)
	for i := range out {
		out[i] = account{
			email:    fmt.Sprintf("loadtest-user-%d@loadtest.local", i+1),
			password: accountPassword,
		}
	}
	return out
}

// seedIP gives each seed request its own limiter bucket. Without this, a rerun
// within the same minute would 429 partway through seeding.
func seedIP(i int) string { return fmt.Sprintf("198.19.0.%d", i+1) }

// seed creates the accounts if they are missing, then proves each one can log
// in. Both halves are deliberately loud: if the DB is half-migrated or the
// password rules changed, we want to know before 100 goroutines start.
func seed(ctx context.Context, client *http.Client, baseURL string) ([]account, error) {
	accts := accounts()

	fmt.Println("seeding accounts...")
	for i, a := range accts {
		status, body, err := postJSON(ctx, client, baseURL+"/api/v1/auth/register", seedIP(i), map[string]string{
			"email":    a.email,
			"password": a.password,
		})
		if err != nil {
			return nil, fmt.Errorf("register %s: %w", a.email, err)
		}
		switch status {
		case http.StatusCreated:
			fmt.Printf("  created  %s\n", a.email)
		case http.StatusConflict:
			fmt.Printf("  exists   %s\n", a.email)
		default:
			return nil, fmt.Errorf("register %s: unexpected status %d: %s", a.email, status, strings.TrimSpace(body))
		}
	}

	fmt.Println("verifying logins...")
	for i, a := range accts {
		status, body, err := postJSON(ctx, client, baseURL+"/api/v1/auth/login", seedIP(i), map[string]string{
			"email":    a.email,
			"password": a.password,
		})
		if err != nil {
			return nil, fmt.Errorf("login %s: %w", a.email, err)
		}
		// Login answers 201, not 200.
		if status != http.StatusCreated {
			return nil, fmt.Errorf("login %s: expected 201, got %d: %s", a.email, status, strings.TrimSpace(body))
		}
		fmt.Printf("  ok       %s\n", a.email)
	}

	return accts, nil
}

// clearLockouts deletes the per-account failure counters for the seeded
// accounts before a run.
//
// Without this, a single locked account poisons the whole test: the harness
// picks accounts at random, so one locked account out of five turns 20% of
// traffic into 429s that never reach the password check, and throughput reads
// low for a reason that has nothing to do with capacity.
//
// It deletes the five specific keys rather than everything matching
// loginlock:*, so pointing the harness at a shared environment can't clear a
// real user's lockout.
func clearLockouts(ctx context.Context, addr string, accts []account) error {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("connecting to redis at %s: %w", addr, err)
	}

	keys := make([]string, len(accts))
	for i, a := range accts {
		keys[i] = redis_db.LockoutKey(a.email)
	}

	n, err := rdb.Del(ctx, keys...).Result()
	if err != nil {
		return fmt.Errorf("clearing lockouts: %w", err)
	}
	fmt.Printf("cleared %d login lockout(s) across %d test accounts\n", n, len(accts))
	return nil
}

// postJSON is the low-traffic helper used by seeding only. The load phases build
// their requests inline so they can reuse a single buffer and skip reading bodies
// into memory.
func postJSON(ctx context.Context, client *http.Client, url, xff string, payload any) (int, string, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", xff)

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

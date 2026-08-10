package ratelimit

import (
	"context"
	"strings"
	"time"
)

// The IP limiter in routes.go caps how fast one source can guess. It does
// nothing against an attacker spreading guesses for a single known account
// across many genuine IPs, so this counter is keyed on the account instead.
const (
	MaxLoginFailures = 5
	LockoutWindow    = 15 * time.Minute
	lockoutPrefix    = "loginlock:"
)

// LockoutKey is exported so tooling (cmd/loadtest) clears the same keys the
// server writes instead of hardcoding the prefix and drifting from it.
//
// Emails are normalized for the key only. The DB lookup still uses whatever the
// client sent, so this changes nothing about which account is matched — it just
// stops case variations from each getting their own failure budget.
func LockoutKey(email string) string {
	return lockoutPrefix + strings.ToLower(strings.TrimSpace(email))
}

// RecordFailure counts one failed login against an account and starts the
// expiry window on the first failure.
func RecordFailure(ctx context.Context, email string) error {
	key := LockoutKey(email)
	count, err := Client.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if count == 1 {
		return Client.Expire(ctx, key, LockoutWindow).Err()
	}
	return nil
}

// IsLocked reports whether an account has spent its failure budget, and how long
// is left on the window.
//
// A Redis error returns false: if the counter is unreachable we fall back to the
// IP limiter and the password check rather than locking every account in the
// system out at once.
func IsLocked(ctx context.Context, email string) (bool, time.Duration) {
	key := LockoutKey(email)
	count, err := Client.Get(ctx, key).Int64()
	if err != nil || count < MaxLoginFailures {
		return false, 0
	}

	ttl, err := Client.TTL(ctx, key).Result()
	if err != nil || ttl < 0 {
		ttl = LockoutWindow
	}
	return true, ttl
}

// ResetFailures clears the lockout counter after a successful login
func ResetFailures(ctx context.Context, email string) error {
	return Client.Del(ctx, LockoutKey(email)).Err()
}

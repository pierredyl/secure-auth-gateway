# Secure Auth Gateway

A Go authentication service. It registers and authenticates users against Postgres, issues encrypted
PASETO session tokens, and throttles abuse at two layers backed by Redis. It runs as three stateless
replicas behind an nginx load balancer.

---

## Quick start

Requires Docker and Docker Compose. Go 1.26+ is needed only for the load-test harness.

**1. Create `.env`:**

```bash
KEY=<64 hex characters>
DATABASE_URL=postgres://postgres:password@localhost:5432/auth_db?sslmode=disable
REDIS_URL=localhost:6379
PORT=8080
```

`KEY` is hex-decoded at startup and must yield exactly 32 bytes. Generate one with
`openssl rand -hex 32`. The `DATABASE_URL` and `REDIS_URL` above apply when running the binary on
the host; Compose overrides both with in-network addresses and passes `KEY` through from your
environment.

**2. Start the stack:**

```bash
docker compose up -d --build
```

nginx publishes port `80`; the app replicas publish nothing. Postgres (`5432`) and Redis (`6379`)
are published for tooling.

**3. Call it:**

```bash
curl http://localhost/api/v1/health
```

```bash
curl -X POST http://localhost/api/v1/auth/register -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"a-long-enough-password"}'
```

```bash
curl -i -X POST http://localhost/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"a-long-enough-password"}'
```

Login returns `201` and sets the token in a `Set-Cookie` header; `-i` makes it visible. Passwords
are 15–72 characters.

---

## Endpoints

| Method | Path | Throttling | Responses |
|---|---|---|---|
| `GET` | `/api/v1/health` | None | `200` `{"status":"ok"}` |
| `POST` | `/api/v1/auth/register` | 10/min per IP | `201` with `id`, `email`, `created_at` · `409` email exists · `422` validation · `400` malformed JSON |
| `POST` | `/api/v1/auth/login` | 10/min per IP + per-account lockout | `201` with `id`, `email`, sets `access_token` cookie · `401` failure · `429` + `Retry-After` when locked · `400` malformed input |

Login returns the same status, body, and elapsed time for an unknown email as for a wrong password,
so it cannot be used to find out which emails are registered.

## Configuration

| Variable | Purpose | Notes |
|---|---|---|
| `KEY` | PASETO symmetric key | 64 hex characters (32 bytes). Startup fails if missing or the wrong length |
| `DATABASE_URL` | Postgres connection string | Used by the pool and the migrator. Retried 10× at 2s intervals |
| `REDIS_URL` | Redis address (`host:port`) | Backs the rate limiter and the lockout counter. Retried 10× at 2s intervals |
| `PORT` | Listen port | Defaults to `8080` |

---

## Architecture

```
cmd/api/            Entry point: env, token maker, DB connect + migrate, Redis connect, server
cmd/loadtest/       Load-test harness (see cmd/loadtest/README.md)
internal/
  auth/             PASETO token maker + Argon2id hashing
  db/               pgx connection pool, embedded golang-migrate migrations
  handlers/         Register, login, health, route registration
  middleware/       Token authentication (AuthenticateToken), role enforcement (RequireRole),
                    security headers
  ratelimit/        Redis client, shared httprate counter, per-account login lockout
Dockerfile          Multi-stage build, static binary on Alpine
docker-compose.yml  Postgres + Redis + 3 app replicas + nginx
nginx.conf          Round-robin load balancer, sets X-Forwarded-For
```

Requests go: client → nginx (`:80`) → one of `app1`/`app2`/`app3` → shared Postgres and Redis. nginx
appends the caller to `X-Forwarded-For`; the app derives the client IP with
`ClientIPFromXFF("172.16.0.0/12")`, walking the header right to left and skipping Docker bridge
addresses. That IP is the rate-limiter key.

The replicas hold no state: sessions live in the token, throttling counters in Redis, users in
Postgres.

### Schema

Migrations are embedded with `go:embed` and applied at startup.

```sql
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role          VARCHAR(50) NOT NULL DEFAULT 'user'
);
```

---

## Design decisions

- **PASETO, not JWT.** JWT's algorithm agility causes real vulnerabilities (`alg=none`,
  RS256→HS256 confusion). PASETO pins the algorithm to the protocol version. `v2.local` encrypts the
  claims, so the client cannot read the embedded role or user ID.
- **Argon2id, not bcrypt.** Memory-hard, so GPU and ASIC cracking scale badly against it. Parameters
  are constants and can be raised without invalidating existing hashes.
- **Authentication and authorization are separate middleware.** `AuthenticateToken` validates the
  token; `RequireRole` checks the claim. A change to one cannot weaken the other.
- **Throttling counters live in Redis.** With three replicas, an in-memory counter gives an attacker
  three times the budget and resets on every deploy.
- **Two throttles, two threat models.** The per-IP limiter caps one source. It does nothing against
  guesses at one account spread across many IPs, so a second counter is keyed on the account.
- **Both login failures cost the same.** An unknown email is verified against a precomputed dummy
  hash, so it takes as long as a real account with a wrong password. The response bodies are
  identical.
- **Register checks the email before hashing.** A duplicate registration costs a SELECT instead of
  19 MiB of Argon2id work.

## Security controls

| Control | Implementation | Defends against |
|---|---|---|
| Password storage | Argon2id (`t=2`, `m=19 MiB`, `p=1`), 16-byte CSPRNG salt, constant-time compare | Offline cracking, rainbow tables, comparison timing leaks |
| Session tokens | PASETO `v2.local`, encrypted, 15-minute TTL | Forgery, tampering, claim disclosure, long-lived theft |
| Token delivery | `HttpOnly`, `SameSite=Strict` cookie | XSS token exfiltration, CSRF |
| Authorization | `RequireRole`, exact match, fails closed on empty context | Privilege escalation |
| Rate limiting (per IP) | 10 req/min on `/auth/*`, counter shared across replicas in Redis, client IP from `X-Forwarded-For` | Online guessing, credential stuffing |
| Account lockout (per email) | 5 failures in 15 minutes, normalized email key, checked before the DB query and before hashing | Distributed guessing at one account |
| Response uniformity | Identical status and body on login failure; dummy-hash verification on the not-found path | Account enumeration by response and by timing |
| Transport hardening | `X-Frame-Options`, CSP `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, HSTS | Clickjacking, MIME-sniffing, SSL-strip MITM |
| Resource exhaustion | Read (5s), write (10s), idle (120s) server timeouts | Slow-request exhaustion |
| Key handling | 32-byte key, hex-encoded in the environment; startup fails if invalid | Hardcoded secrets |

---

## Load testing

`cmd/loadtest` drives the stack through nginx with concurrent simulated users, separating two
questions: whether the throttling works, and what a login costs once Argon2id and the Postgres round
trip are in the path. A `health` target measures the same stack with neither, as a baseline.

```bash
go run ./cmd/loadtest
```

Phases, flags, and how to read the output: [cmd/loadtest/README.md](cmd/loadtest/README.md).

---

## Limitations

- **No protected endpoints.** `AuthenticateToken` and `RequireRole` are implemented but no route
  currently sits behind them.
- **The session cookie is not consumed.** Login sets an `access_token` cookie; `AuthenticateToken`
  reads the `Authorization: Bearer` header. The cookie is also set with `Secure: false` for local
  `http://` and must be flipped before deployment.
- **No token revocation.** A stolen token is valid until its 15-minute expiry. Refresh-token
  rotation with a revocation list is the next step.
- **No MFA.**
- **Register discloses whether an email exists** via `409`, which login does not. It needs its own
  throttling in production.
- **Lockout fails open.** If Redis is unreachable, `IsLocked` returns false rather than locking out
  every account at once; the IP limiter and password check still apply.
- **The trusted proxy range is hardcoded** to `172.16.0.0/12`, matching the Docker bridge. A wrong
  prefix lets clients choose their own rate-limiter key by forging `X-Forwarded-For`.
- **TLS is assumed upstream.** The stack speaks plaintext; HSTS only means something behind a
  TLS-terminating proxy.
- **The register response carries empty `role` and `password_hash` fields**, because its `201` body
  shares a struct with login. Nothing is leaked; the shape is misleading.
- **No automated tests.** Verification is `curl` and the load harness.
- **Compose ships development credentials** (`postgres`/`password`, unauthenticated Redis).

---

## Tech stack

Go · [chi](https://github.com/go-chi/chi) (routing) ·
[o1egl/paseto](https://github.com/o1egl/paseto) (tokens) ·
[x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) (hashing) ·
[validator](https://github.com/go-playground/validator) (validation) ·
[httprate](https://github.com/go-chi/httprate) +
[httprate-redis](https://github.com/go-chi/httprate-redis) (rate limiting) ·
[pgx](https://github.com/jackc/pgx) (Postgres) ·
[golang-migrate](https://github.com/golang-migrate/migrate) (migrations) ·
[go-redis](https://github.com/redis/go-redis) ·
[godotenv](https://github.com/joho/godotenv)

Postgres 16 · Redis 7 · nginx · Docker Compose

## License

See [LICENSE](./LICENSE).

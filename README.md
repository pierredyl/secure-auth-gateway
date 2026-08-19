# Secure Auth Gateway

A Go authentication service. It registers and authenticates users against Postgres, issues
Ed25519-signed PASETO access tokens that any other service can verify from a published public key,
rotates single-use refresh tokens through Redis, and throttles abuse at two layers. It runs as three
stateless replicas behind an nginx load balancer that terminates TLS.

Access tokens travel in an `Authorization: Bearer` header; refresh tokens travel in an HttpOnly
cookie and never leave this service.

Integrating a service against it: [docs/TOKEN_CONTRACT.md](docs/TOKEN_CONTRACT.md).

---

## Quick start

Requires Docker and Docker Compose. Go 1.26+ is needed only for the load-test harness.

**1. Create `.env`:**

```bash
ACCESS_TOKEN_PRIVATE_KEY=<128 hex characters>
REFRESH_TOKEN_KEY=<64 hex characters>
DATABASE_URL=postgres://postgres:password@localhost:5432/auth_db?sslmode=disable
REDIS_URL=localhost:6379
PORT=8080
```

Generate both keys with:

```bash
go run ./cmd/keygen
```

`ACCESS_TOKEN_PRIVATE_KEY` is an Ed25519 private key (64 bytes) used to sign access tokens; the
matching public key is derived at startup and published, so there is no second variable to keep in
sync. `REFRESH_TOKEN_KEY` is a 32-byte symmetric key. Both are hex-decoded at startup and the
service refuses to start if either is missing or the wrong length.

The `DATABASE_URL` and `REDIS_URL` above apply when running the binary on the host; Compose
overrides both with in-network addresses and passes the keys through from your environment. All
three replicas must share the same keys, or a token signed by one will not verify on another.

**2. Generate the dev TLS certificate:**

```bash
bash scripts/gen-dev-cert.sh
```

nginx will not start without `certs/dev.crt` and `certs/dev.key`. The cert is self-signed because no
public domain exists here for a real CA to issue against, so clients must skip verification
(`curl -k`). `certs/` is gitignored; the script is idempotent.

**3. Start the stack:**

```bash
docker compose up -d --build
```

nginx publishes `443` (the service), `80` (301s to 443), and `8081` (`stub_status`). The app replicas
publish nothing. Postgres (`5432`) and Redis (`6379`) are published for tooling.

`make up`, `make down`, `make ps`, `make logs` and `make test` wrap the same commands; `make help`
lists everything.

**4. Call it:**

```bash
curl -k https://localhost/api/v1/health
```

```bash
curl -k -X POST https://localhost/api/v1/auth/register -H "Content-Type: application/json" -d "{\"email\":\"user@example.com\",\"password\":\"a-long-enough-password\"}"
```

```bash
curl -k -i -X POST https://localhost/api/v1/auth/login -H "Content-Type: application/json" -d "{\"email\":\"user@example.com\",\"password\":\"a-long-enough-password\"}"
```

Login returns `201` with the access token in the JSON body. The `Set-Cookie` header that `-i` reveals
carries the *refresh* token, not the access token. Passwords are 15–72 characters.

```bash
curl -k https://localhost/api/v1/user/health -H "Authorization: Bearer <access_token>"
```

---

## Endpoints

| Method | Path | Auth / throttling | Responses |
|---|---|---|---|
| `GET` | `/api/v1/health` | None | `200` `{"status":"ok"}` |
| `GET` | `/.well-known/paseto-public-key` | None | `200` with `algorithm`, `paseto_version`, `key_id`, hex `public_key` |
| `POST` | `/api/v1/auth/register` | 10/min per IP | `201` `{message, data{id, role, email, created_at}}` · `409` email exists · `422` validation · `400` malformed JSON |
| `POST` | `/api/v1/auth/login` | 10/min per IP + per-account lockout | `201` `{message, access_token}`, sets `refresh_token` cookie · `401` failure · `429` + `Retry-After` when locked · `400` malformed input |
| `POST` | `/api/v1/auth/refresh` | 10/min per IP | `201` `{message, access_token}`, rotates the cookie · `401` on a missing, invalid, expired or already-redeemed token |
| `GET` | `/api/v1/admin/health` | Bearer token + `role=admin` | `200` · `401` no/invalid token · `403` wrong role |
| `GET` | `/api/v1/user/health` | Bearer token + `role=user` | `200` · `401` no/invalid token · `403` wrong role |

Login returns the same status, body, and elapsed time for an unknown email as for a wrong password,
so it cannot be used to find out which emails are registered.

Refresh is single-use. Redis `GetDel` claims and invalidates the stored token in one atomic
operation, so a replayed token gets `401` and two concurrent redemptions cannot both win.

The two `*/health` routes behind the token check are placeholders — they exist to exercise the role
gate, not to do work.

## Configuration

| Variable | Purpose | Notes |
|---|---|---|
| `ACCESS_TOKEN_PRIVATE_KEY` | Ed25519 private key, signs access tokens | 128 hex characters (64 bytes). The public half is derived at startup. Startup fails if missing or the wrong length |
| `REFRESH_TOKEN_KEY` | PASETO symmetric key for refresh tokens | 64 hex characters (32 bytes). Startup fails if missing or the wrong length |
| `DATABASE_URL` | Postgres connection string | Used by the pool and the migrator. Retried 10× at 2s intervals |
| `REDIS_URL` | Redis address (`host:port`) | Backs the rate limiter and the lockout counter. Retried 10× at 2s intervals |
| `PORT` | Listen port | Defaults to `8080` |

Compose additionally sets `GOMAXPROCS=3` on each replica. Go reads the host's CPU count, not the
cpuset, so three replicas left alone would start 36 scheduler threads against the 8 cores they share,
every one of them able to hold a 19 MiB Argon2id buffer.

---

## Architecture

```
cmd/api/            Entry point: env, token signer, DB connect + migrate, Redis, server,
                    graceful shutdown, private pprof listener on :6060
cmd/keygen/         Prints a fresh ACCESS_TOKEN_PRIVATE_KEY and REFRESH_TOKEN_KEY for .env
cmd/loadtest/       Load generator (see cmd/loadtest/README.md)
cmd/loadreport/     Merges a run's JSON summary and CPU samples into one markdown report
internal/
  auth/             AccessTokenSigner (Ed25519), RefreshTokenMaker (v2.local), Argon2id hashing
  db/               pgx connection pool, embedded golang-migrate migrations
  handlers/         Register, login, refresh, health, public key, role-gated stubs, routes
  middleware/       Role enforcement (RequireRole)
  redis_db/         Redis client, shared httprate counter, per-account login lockout
pkg/
  pasetoauth/       Public, importable: token Verifier, AuthenticateToken and SecurityHeaders
                    middleware — what a third-party Go service imports
docs/               TOKEN_CONTRACT.md (integration contract), LOADTEST.md (harness runbook)
examples/
  verify-token/     Standalone module that verifies a token with only the published public key
  verify-token-pkg/ The same, but importing pkg/pasetoauth instead of a raw PASETO library
scripts/            gen-dev-cert.sh, loadtest.sh, compose.sh, win-env.sh
results/            One markdown + JSON report per load-test run
Makefile            Stack and load-test entry points; run `make help`
Dockerfile          Multi-stage build, static binary on Alpine
Dockerfile.loadtest Generator + report binaries, so the harness runs inside the compose network
docker-compose.yml  Postgres + Redis + 3 app replicas + nginx, CPU-pinned and healthchecked
nginx.conf          TLS termination, 80→443 redirect, round-robin, upstream keepalive pool
```

Requests go: client → nginx (`:443`, TLS) → one of `app1`/`app2`/`app3` → shared Postgres and Redis.
nginx appends the caller to `X-Forwarded-For`; the app derives the client IP with
`ClientIPFromXFF("172.16.0.0/12")`, walking the header right to left and skipping Docker bridge
addresses. That IP is the rate-limiter key.

The replicas hold no state: sessions live in the token, throttling counters and refresh tokens in
Redis, users in Postgres.

### Operational

- **Graceful shutdown.** SIGINT/SIGTERM stops the accept loop and drains in-flight requests for up to
  10 seconds before the pool is closed.
- **pprof runs on its own listener and its own mux (`:6060`).** nginx proxies `location /`, so
  anything on the chi router is reachable from the public port, and `/debug/pprof/heap` on a service
  handling password hashes is a disclosure. Port 6060 is not published — reach it with
  `docker compose exec app1 wget -qO- localhost:6060/debug/pprof/`.
- **Replicas wait on healthchecks.** `depends_on` is gated on `pg_isready` and `redis-cli ping`, not
  on container start.
- **CPU pinning.** Services under test run on cores 0-7, the load generator on 8-11, so a throughput
  number is reproducible rather than a statement about the machine.
- **nginx tuning.** `worker_processes auto`, `worker_connections 16384`, and a 128-connection
  keepalive pool to the upstreams. Mounting a config over `/etc/nginx/nginx.conf` replaces the
  image's settings rather than extending them, which is why these are restated explicitly.

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
  RS256→HS256 confusion). PASETO pins the algorithm to the protocol version.
- **Access tokens are signed (`v2.public`), refresh tokens are encrypted (`v2.local`).** A symmetric
  key cannot be shared: anyone able to verify a token with it can also forge one. Signing access
  tokens with Ed25519 lets other services verify them from a published public key while leaving
  forgery impossible without the private half. Refresh tokens never leave this service — they are
  issued and redeemed here — so they stay symmetric rather than taking on key distribution for
  nothing. The tradeoff is that access token claims are readable by the bearer; see
  [docs/TOKEN_CONTRACT.md](docs/TOKEN_CONTRACT.md).
- **The signer and the verifier are separate types.** `AccessTokenSigner` holds the private key,
  `Verifier` holds only the public key. The authentication middleware receives a verifier, so the
  code path that checks tokens structurally cannot mint them.
- **Access token in the response body, refresh token in a cookie.** The access token has to reach an
  `Authorization` header, which means the client has to be able to read it. The refresh token must
  not be readable, so it is HttpOnly and scoped to `Path=/api/v1/auth` — it reaches only the
  endpoints that redeem it, not every request.
- **Refresh tokens are single-use.** Redemption is a Redis `GetDel`: one atomic operation that reads
  the token's owner and deletes the record, so a replay finds nothing and two concurrent redemptions
  cannot both succeed.
- **The stack terminates TLS.** The refresh cookie is `Secure`, and browsers silently discard
  `Secure` cookies over plaintext. Serving real traffic on `:80` would leave the refresh flow quietly
  broken instead of obviously broken, so `:80` does nothing but redirect.
- **Argon2id** Memory-hard, so GPU and ASIC cracking scale badly against it. Parameters
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
| Access tokens | PASETO `v2.public`, Ed25519-signed, 15-minute TTL | Forgery, tampering, long-lived theft |
| Refresh tokens | PASETO `v2.local`, encrypted, 30-day TTL, single-use rotation via Redis `GetDel` | Forgery, replay of a redeemed token, claim disclosure |
| Key separation | Private key confined to `AccessTokenSigner`; middleware and the public endpoint receive verify-only material | A verification path being repurposed to sign |
| Token delivery | Refresh token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/api/v1/auth`; access token returned in the body and presented as a Bearer header | XSS refresh-token exfiltration, CSRF, cookie replay on unrelated paths |
| Authorization | `RequireRole`, exact match, fails closed on empty context | Privilege escalation |
| Rate limiting (per IP) | 10 req/min on `/auth/*`, counter shared across replicas in Redis, client IP from `X-Forwarded-For` | Online guessing, credential stuffing |
| Account lockout (per email) | 5 failures in 15 minutes, normalized email key, checked before the DB query and before hashing | Distributed guessing at one account |
| Response uniformity | Identical status and body on login failure, dummy-hash verification on the not-found path; one collapsed response for every refresh failure | Account enumeration by response and by timing; probing which refresh check failed |
| Transport | TLS 1.2/1.3 terminated at nginx, `:80` 301s to `:443`, HSTS `max-age=63072000; includeSubDomains` | Plaintext interception, SSL-strip MITM |
| Response hardening | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` | Clickjacking, MIME-sniffing |
| Profiling surface | pprof bound to `:6060` on a separate mux, unproxied and unpublished | Heap and goroutine disclosure from a service holding password material |
| Resource exhaustion | Read (5s), write (10s), idle (120s) server timeouts; nginx `proxy_connect_timeout 2s` | Slow-request exhaustion |
| Availability under load | nginx `max_fails=3 fail_timeout=5s` per upstream, keepalive pool, 10s drain on shutdown | One transient failure removing a third of capacity; in-flight requests dropped on deploy |
| Key handling | Keys hex-encoded in the environment, never in source; startup fails if invalid | Hardcoded secrets |

---

## Load testing

`cmd/loadtest` drives the stack through nginx, separating two questions: whether the throttling
works, and what a login costs once Argon2id and the Postgres round trip are in the path. A `health`
target measures the same stack with neither, as a baseline.

One repeatable run at one concurrency level, ending in one markdown report:

```bash
make loadtest CONCURRENCY=200
```

That brings the stack up, samples `docker stats` across the six services under test for the length of
the run, and writes `results/loadtest_200_<timestamp>.md` covering throughput, tail latency, error
rate and CPU saturation. Concurrency is the controlled variable — invoke it once per level and
compare the reports.

Closed-loop, `think=0`, `GET /api/v1/health`, stack pinned to 8 cores with the generator pinned
outside them:

| Concurrency | Via | Throughput | p99 | Errors | Avg CPU of 8 cores |
|---|---|---|---|---|---|
| 50 | `https://nginx:443` | 12,125 req/s | 23.3ms | 0 | 75.4% |
| 100 | `http://nginx:80` | 5,934 req/s | 72.4ms | 0 | 58.3% |
| 200 | `http://nginx:80` | 8,548 req/s | 86.6ms | 0 | 58.0% |
| 500 | `http://nginx:80` | 9,259 req/s | 177.5ms | 0 | 64.5% |

The three higher-concurrency runs predate TLS termination and went in over plaintext `:80`. They are
not directly comparable to the 50-user row, and the sweep needs rerunning over HTTPS.

Login is measured separately, open-loop — the highest fixed arrival rate held with zero errors:
**~80 req/s, p50 47.7ms, p99 136ms**. That is ~100x slower than health by design; Argon2id at 19 MiB
per attempt is what makes a stolen password database expensive to attack. A small gap would instead
mean the stack itself was the limit and tuning Argon2id would buy nothing.

nginx answers `/nginx-noop` itself without touching Go. Whatever it reaches is the ceiling of
everything that is *not* this code — generator, network, nginx — so if it and `/api/v1/health` top
out at the same number, the Go app was never the thing being measured.

Runbook, how to read a report, and the tunables: [docs/LOADTEST.md](docs/LOADTEST.md). Generator
phases and flags: [cmd/loadtest/README.md](cmd/loadtest/README.md).

---

## Limitations

- **No key rotation.** One signing key, fixed at startup. `key_id` is in the public key response so
  a rollover can be expressed later, but nothing consumes it yet and rotating means a restart that
  invalidates every outstanding access token.
- **No token revocation.** A stolen access token is valid until its 15-minute expiry. Refresh tokens
  are single-use and revoked on redemption, but access tokens are not checked against any list.
- **No MFA.**
- **No logout.** Refresh tokens expire or are consumed; nothing clears a session on demand.
- **Register discloses whether an email exists** via `409`, which login does not. It needs its own
  throttling in production.
- **Lockout fails open.** If Redis is unreachable, `IsLocked` returns false rather than locking out
  every account at once; the IP limiter and password check still apply.
- **The trusted proxy range is hardcoded** to `172.16.0.0/12`, matching the Docker bridge. A wrong
  prefix lets clients choose their own rate-limiter key by forging `X-Forwarded-For`.
- **TLS uses a self-signed dev certificate.** Every client has to skip verification. A real
  deployment needs a CA-issued cert; nothing else in the config changes.
- **Tests cover the token layer only.** `internal/auth` and `pkg/pasetoauth` have unit tests,
  including forgery, tamper and expiry rejection; the handlers and middleware are still verified by
  `curl` and the load harness.
- **The load harness cannot drive token validation.** It discards login response bodies and keeps no
  per-user token state, so the authenticated routes are never exercised under load.
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

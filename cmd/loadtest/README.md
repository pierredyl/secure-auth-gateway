# loadtest

Simulates real users against the gateway. Five fixed accounts, N concurrent virtual users, each
request carrying its own client IP.

Two endpoints can be targeted:

| `-target` | Endpoint | Question it answers |
|---|---|---|
| `login` (default) | `POST /api/v1/auth/login` | How much *authentication* can this handle, and does the throttling work? |
| `health` | `GET /api/v1/health` | How much raw traffic can the stack handle with no hashing and no database? |

## Prerequisites

```bash
docker compose up -d --build
```

The app replicas publish no ports — all traffic goes through nginx on `localhost:80`. Redis is
published on `localhost:6379`, which the harness uses to clear login lockouts (see below).

## Quick start

```bash
go run ./cmd/loadtest
```

That clears the test accounts' lockouts, seeds the accounts (idempotently), runs the limiter
phase, cools down, runs the compute phase, and prints both reports.

## Why every request spoofs X-Forwarded-For

`internal/handlers/routes.go` rate-limits with `httprate.Limit(10, 1*time.Minute)` keyed on the
IP that `chiMiddleware.ClientIPFromXFF("172.16.0.0/12")` derives. That middleware walks
`X-Forwarded-For` right to left and skips anything inside `172.16.0.0/12`.

Traffic sent from the host through published port 80 arrives at nginx from the Docker bridge
gateway — a `172.x` address, i.e. trusted, i.e. skipped. The key resolves to the empty string
and **every client on earth shares one bucket capped at 10 requests per minute**. A load test
that didn't spoof would flatline in the first second and measure nothing.

So the harness sets `X-Forwarded-For` itself, using addresses from `198.18.0.0/15` (the RFC
2544 benchmarking range) which sit outside the trusted prefix. nginx appends to the header
rather than replacing it, so the value we send survives the walk and becomes the limiter key.

## The two phases

| Phase | IPs | Measures |
|---|---|---|
| `limiter` | shared bucket of `-ips` addresses, round-robin | 429 onset, how many requests each IP is admitted, whether `Retry-After` / `X-RateLimit-*` come back |
| `compute` | a fresh address per request | real login cost: Argon2id hashing (19 MiB per hash) plus the Postgres round trip |

They exist separately because they fight each other. A 429 is rejected in middleware *before*
Argon2id runs, so a run where 96% of requests are throttled says nothing about compute cost —
and a run tuned to avoid throttling never tests the limiter.

Pressure on the limiter is set by bucket size relative to load:

```
offered req/min per IP = users / think_seconds * 60 / ips
```

Defaults (`-users=100 -think=1s -ips=25`) offer ~240 req/min per IP against a 10 req/min limit,
so most requests should be throttled. The harness prints this figure before the phase starts.

## `-target=health` — the capacity baseline

`GET /api/v1/health` does no hashing, no database work and no authentication, and has no rate
limit. Because of that it runs differently from `login`:

- **Single phase.** No limiter/compute split — with no rate limit there's only one question.
- **No seeding, no accounts, no lockout clearing.** Nothing about it touches user state.
- **Still spoofs `X-Forwarded-For`** (a fresh IP per request) so it passes through the exact
  same global middleware chain as login. The comparison stays apples-to-apples.
- **Success is `200`,** where login answers `201`. The report labels this automatically.

Its whole purpose is comparison. The login ceiling is dominated by Argon2id, which is expensive
*on purpose*. Running both separates "the security setting I chose costs this much" from "my
stack is slow":

```bash
go run ./cmd/loadtest -target=health -users=100 -duration=20s -think=0
go run ./cmd/loadtest -target=login -phase=compute -users=100 -duration=20s -think=0 -skip-seed
```

Use `-think=0` for both when you want maximum throughput rather than a paced simulation —
otherwise the harness's own pacing (`users / think`) caps the rate long before the server does.

Measured on a 12-core host, 100 users, `-think=0`:

| Target | Throughput | p50 | p95 |
|---|---|---|---|
| `health` | ~2,500 req/s | 36ms | 74ms |
| `login` | ~105 req/s | 778ms | 2,160ms |

A ~24x gap says the plumbing is fine and hashing is the entire cost. A small gap would mean the
stack itself is the limit and tuning Argon2id wouldn't buy much.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-url` | `http://localhost:80` | Base URL |
| `-target` | `login` | Endpoint under test: `login` (two-phase) or `health` (raw capacity) |
| `-users` | `100` | Concurrent virtual users — the main dial |
| `-duration` | `30s` | Length of each phase |
| `-think` | `1s` | Pause between a user's requests (±20% jitter) |
| `-ips` | `25` | IP bucket size in the limiter phase |
| `-phase` | `both` | `limiter`, `compute`, or `both` |
| `-cooldown` | `65s` | Gap between phases so limiter windows expire |
| `-timeout` | `10s` | Per-request timeout |
| `-ramp` | `0s` | Stagger user start over this window |
| `-seed-only` | `false` | Create the accounts and exit |
| `-skip-seed` | `false` | Skip seeding entirely |
| `-redis` | `localhost:6379` | Redis address used to clear the test accounts' lockouts |
| `-keep-lockouts` | `false` | Don't clear lockouts before running |
| `-csv` | — | Dump raw per-request samples to this path |

## Accounts

Exactly five, always the same, never more:

```
loadtest-user-1@loadtest.local … loadtest-user-5@loadtest.local
```

Seeding treats `409 Email already registered` as success, so reruns don't add rows. Each seed
request uses its own IP (`198.19.0.1`–`.5`) so back-to-back runs never throttle themselves
during setup. After registering, every account is logged in once to prove the credentials work
before the load starts.

### Login lockouts are cleared automatically

The server locks an account after 5 failed logins in 15 minutes
(`internal/ratelimit/lockout.go`), keyed on the account rather than the IP. A locked account
rejects **the correct password too**, and the harness picks accounts at random — so one locked
account out of five silently turns ~20% of a run into 429s that never reach the password check,
and throughput reads low for a reason that has nothing to do with capacity.

So before every `login` run the harness deletes the five accounts' lockout keys from Redis via
`-redis`. It deletes those five keys specifically, using the same `ratelimit.LockoutKey` helper
the server writes with — never a wildcard sweep — so pointing the harness at a shared
environment can't clear a real user's lockout.

If Redis isn't reachable it warns and continues rather than failing; pass `-keep-lockouts` to
skip the step deliberately, e.g. when you're *testing* the lockout itself.

## Reading the output

- **`201 accepted`** (`200` for health) — the full request path. This min/max/p95 is the real
  capacity number.
- **`429 rejected`** — should be 1–3 ms. If these climb, the throttling itself is the bottleneck.
- **`429 breakdown`** — which throttle fired. `ip limiter` is the 10/min per-IP rule;
  `account lockout` is the per-account failure counter. They return the same status code, so
  the harness tells them apart by headers (only httprate sends `X-RateLimit-*`).
- **`admitted per IP`** — should land near `10 × minutes of run`. A max well above that means
  the Redis counter isn't being shared correctly across the three replicas.
- **`transport errors`** — timeouts mean slow, `reset / EOF` and `connection refused` mean
  something fell over.
- **A `WARNING`** fires if the compute phase hits the *IP limiter* — that means the spoofing
  stopped working and those latency numbers are invalid.
- **A `NOTE`** fires if it hits *account lockouts* — not a harness bug, but a share of the run
  never reached the password check, so throughput is understated. Shouldn't happen now that
  lockouts are cleared automatically; if it does, check the `-redis` address.

The two phases' accepted latencies are **not** comparable. The limiter admits almost all of its
traffic in the first few seconds, before any window has filled — a cold thundering-herd burst —
whereas the compute phase spreads the same offered load across the whole run. Read the compute
phase for capacity and the limiter phase for throttling behaviour.

## Examples

Create the accounts and exit:

```bash
go run ./cmd/loadtest -seed-only
```

Quick smoke test — expect all successes, no 429s:

```bash
go run ./cmd/loadtest -users=3 -duration=5s -phase=compute -skip-seed
```

Rate limiter in isolation — 4 users squeezed through 2 IPs:

```bash
go run ./cmd/loadtest -users=4 -ips=2 -duration=70s -phase=limiter -skip-seed
```

Raw stack capacity, no hashing:

```bash
go run ./cmd/loadtest -target=health -users=100 -duration=20s -think=0
```

Push login until it breaks (expect 5xx and dropped connections around 400):

```bash
go run ./cmd/loadtest -users=400 -duration=60s -phase=compute -csv=run400.csv
```

Watch the server side at the same time:

```bash
docker stats
```

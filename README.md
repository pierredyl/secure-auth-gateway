# Secure Auth Gateway

A stateless authentication gateway written in Go. It sits at the edge in front
of one or more downstream services, authenticates requests, and enforces
role-based access before traffic ever reaches a protected handler.

The project is a focused demonstration of **secure-by-design authentication**:
password storage with Argon2id, encrypted session tokens with PASETO, and a
clean separation between authentication and authorization. It is built to be
read. The security reasoning behind each decision is documented, not just
implemented.

> **Scope note:** This is a gateway, not a full application. It defines an
> `IdentityStore` contract and expects a real backing store to be supplied by
> the deploying service; the included `MockDB` exists only to exercise the flow
> locally. See [Known limitations](#known-limitations).

---

## Why these choices

The design favors removing entire classes of bugs over patching individual ones.

- **PASETO over JWT.** JWT's algorithm agility is a recurring source of
  real-world vulnerabilities (`alg=none`, RS256→HS256 confusion). PASETO pins
  the algorithm to the protocol version, eliminating that bug class by
  construction. The `v2.local` mode is used, so token claims are *encrypted*,
  not merely signed. The client cannot read the embedded role or user ID.

- **Argon2id over bcrypt.** Argon2id is memory-hard (resistant to GPU/ASIC
  cracking) and is the current OWASP first choice for new systems. Parameters
  follow the OWASP minimum profile and are defined as constants so they can be
  tuned upward as hardware improves, without breaking existing hashes.

- **Authentication and authorization are separate middleware.** "Who are you"
  (token validation) is distinct from "what may you do" (role check). An authz
  change can never accidentally weaken token validation, and each layer is
  independently testable.

- **Protected routes are grouped under the auth middleware**, so a newly added
  route is protected *by default*. You have to opt out, which is the safe
  direction. The classic "forgot to protect the new endpoint" bug is structurally
  harder to introduce.

---

## Security controls

| Control | Implementation | Defends against |
|---|---|---|
| Password storage | Argon2id (`t=2`, `m=19 MiB`, `p=1`), 16-byte CSPRNG salt, constant-time compare | Offline cracking, rainbow tables, comparison timing leaks |
| Session tokens | PASETO `v2.local`, encrypted, 15-minute TTL | Token forgery/tampering, claim disclosure, long-lived theft |
| Authorization | Role middleware, exact-match, fails closed on empty context | Privilege escalation, unauthenticated access to protected routes |
| Transport hardening | `X-Frame-Options`, CSP `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, HSTS | Clickjacking, MIME-sniffing, SSL-strip MITM |
| Abuse resistance | Rate limiting on auth routes (5/min/IP); server read/write/idle timeouts | Online password guessing, slow-request resource exhaustion |
| Key handling | 32-byte symmetric key loaded from environment; startup fails if invalid | Hardcoded-secret exposure |

---

## Architecture

```
cmd/api/            Entry point: wiring, server config, MockDB
internal/
  auth/             PASETO token maker + Argon2id hashing (pure crypto layer)
  handlers/         HTTP handlers, route registration, IdentityStore interface
  middleware/       Auth, role enforcement, security headers
```

The gateway depends on an `IdentityStore` interface, not a concrete database:

```go
type IdentityStore interface {
	CreateUser(email, passwordHash string) error
	GrabUserInformation(email string) (userID, role, passwordHash string, err error)
}
```

Any backing store (Postgres, LDAP, an internal service) satisfies this contract.
The gateway never stores credentials itself.

---

## Getting started

**Requirements:** Go (see `go.mod` for the version).

**1. Set the symmetric key.** The token key is read from the `KEY` environment
variable and must be exactly 32 bytes. Startup fails if it is missing or the
wrong length.

```bash
export KEY="0123456789abcdef0123456789abcdef"   # 32 bytes — DEV ONLY
```

In production this should be a base64-encoded 32 random bytes from a secret
manager, decoded at startup — not a hand-typed ASCII string.

**2. Run the gateway.**

```bash
go run ./cmd/api
# Secure Auth Gateway running on port 8080...
```

**3. Call it.**

```bash
# Register (password must be 15–72 characters)
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"a-long-enough-password"}'

# Log in -> returns an access_token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"<the-seeded-password>"}'

# Reach a protected route with the token
curl http://localhost:8080/api/v1/admin/dashboard \
  -H "Authorization: Bearer <access_token>"
```

---

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Public (rate-limited) | Hashes and stores credentials; returns `201` |
| `POST` | `/api/v1/auth/login` | Public (rate-limited) | Returns an encrypted access token on success |
| `GET` | `/api/v1/admin/dashboard` | Bearer token, `admin` role | Reads identity from verified token context |
| `GET` | `/api/v1/user/profile` | Bearer token, `user` role | Stub endpoint (see limitations) |

Login returns identical responses for "user not found" and "wrong password"
(same status, same body) so the endpoint cannot be used to discover which
emails are registered.

---

## Known limitations

These are deliberate boundaries for this version, documented rather than hidden.

- **Backing store is a mock.** `MockDB` seeds a single admin user and its
  `CreateUser` is a no-op; register-then-login will not round-trip until a real
  `IdentityStore` is supplied. The gateway logic is the artifact here, not the
  storage.
- **No token revocation.** A stolen token is valid until its 15-minute expiry.
  Refresh-token rotation with a server-side revocation list is the planned next
  step.
- **No MFA.** The strongest single mitigation against credential theft and
  online guessing; the highest-value future addition.
- **Timing-based user enumeration.** The "user not found" path returns before
  Argon2 runs, so it responds faster than a real user with a wrong password. The
  response-content leak is closed; this timing twin is not yet (mitigation:
  verify against a dummy hash on the not-found path).
- **Rate limiting is per-process and IP-keyed.** Behind a proxy, `KeyByIP` sees
  the proxy's IP; a real deployment needs proxy-aware key extraction and a shared
  store (e.g. Redis) across instances.
- **TLS is assumed upstream.** The gateway speaks plaintext on an internal
  network; HSTS is meaningful only behind a TLS-terminating proxy.

---

## Tech stack

Go · [chi](https://github.com/go-chi/chi) (routing) ·
[o1egl/paseto](https://github.com/o1egl/paseto) (tokens) ·
[x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) (hashing) ·
[validator](https://github.com/go-playground/validator) (input validation) ·
[httprate](https://github.com/go-chi/httprate) (rate limiting)

## License

See [LICENSE](./LICENSE).

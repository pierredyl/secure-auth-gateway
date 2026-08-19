# Access token contract

This document is for developers building a service that needs to trust access tokens issued by this
gateway. You do not need to run this codebase, import its packages, or write Go — you need the
public key and the claim shape below.

**If you are writing Go**, you can skip most of this document: `go get` this repository and import
[`pkg/pasetoauth`](../pkg/pasetoauth) instead of a raw PASETO library. It gives you a `Verifier` built
from the public key below, and an `AuthenticateToken` middleware (`func(http.Handler) http.Handler`,
so it works with `net/http`, chi, gorilla, or anything else that speaks that signature) that gates
your own routes on these tokens the same way this gateway gates its own. See
[`examples/verify-token-pkg`](../examples/verify-token-pkg) for a complete example. Everyone else —
other languages, or Go developers who'd rather not depend on this repo — should keep reading.

---

## What the token is

Access tokens are **PASETO `v2.public`**: Ed25519-signed, **not encrypted**.

Two consequences, both important:

- **Anyone holding the token can read the claims.** The payload is base64, not ciphertext. Do not
  treat the user ID or role inside it as confidential, and do not add anything sensitive to it.
- **Only this gateway can create one.** The signature is produced with a private key that never
  leaves the service. Verifying with the public key proves the token came from the gateway and has
  not been altered since.

This is a deliberate split from refresh tokens, which are `v2.local` (symmetric, encrypted) and are
never exposed to other services — see [Why two schemes](#why-two-schemes).

## Getting the public key

```
GET /.well-known/paseto-public-key
```

```json
{
  "algorithm": "ed25519",
  "paseto_version": "v2.public",
  "key_id": "access-token-v1",
  "public_key": "5a1c...<64 hex characters>"
}
```

The endpoint is public and unauthenticated. A public key is not a secret — knowing it lets you
verify tokens, never mint them.

`public_key` is hex-encoded and decodes to exactly 32 bytes. Check `algorithm` and `paseto_version`
before using it rather than assuming; that is what makes a future key rollover visible to you
instead of silently breaking verification.

There is currently one key and it changes only on restart. `key_id` exists so that a future rotation
can be expressed without changing this response shape.

## Claim shape

```json
{
  "user_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "role": "admin",
  "IssuedAt": "2026-08-14T10:04:11.482Z",
  "ExpiredAt": "2026-08-14T10:19:11.482Z"
}
```

| Field | Type | Meaning |
|---|---|---|
| `user_id` | string (UUID) | The authenticated user. Stable for the life of the account. |
| `role` | string | Currently `user` or `admin`. Compare exactly; do not assume a hierarchy. |
| `IssuedAt` | RFC 3339 timestamp | When the gateway signed the token. |
| `ExpiredAt` | RFC 3339 timestamp | When it stops being valid. Access tokens live 15 minutes. |

`IssuedAt` and `ExpiredAt` are capitalized because they come from an embedded Go struct with no JSON
tags. That is a quirk of the current serialization, not a style choice — match it exactly.

## Verifying a token

> **Signature verification does not check expiry.** Every PASETO library will happily verify a token
> that expired last week — the signature is still mathematically valid. You must compare `ExpiredAt`
> against the current time yourself. This is the single most common integration mistake.

In Go:

```go
var payload struct {
    UserID    string    `json:"user_id"`
    Role      string    `json:"role"`
    IssuedAt  time.Time `json:"IssuedAt"`
    ExpiredAt time.Time `json:"ExpiredAt"`
}

// publicKey is an ed25519.PublicKey decoded from the endpoint above.
if err := paseto.NewV2().Verify(token, publicKey, &payload, nil); err != nil {
    return fmt.Errorf("token is forged or tampered: %w", err)
}
if time.Now().After(payload.ExpiredAt) {
    return errors.New("token expired")
}
```

A complete, runnable version — fetching the key over HTTP, verifying, and printing the claims — is
in [`examples/verify-token`](../examples/verify-token). It is a separate Go module that imports
nothing from this repository, so it demonstrates exactly what an outside consumer has to write by
hand. [`examples/verify-token-pkg`](../examples/verify-token-pkg) shows the same thing using
`pkg/pasetoauth` instead — same result, no PASETO library of your own required.

In other languages, use a PASETO library that supports `v2.public` and pass it the same 32-byte
key. The token format is a standard, not something specific to this project.

## Sending a token

The gateway's own protected routes expect:

```
Authorization: Bearer v2.public.eyJ1c2VyX2lkIjoi...
```

Clients obtain a token from `POST /api/v1/auth/login`, which returns it in the JSON body as
`access_token`, and renew it through `POST /api/v1/auth/refresh` before the 15 minutes elapse.

## What this does not give you

- **No revocation.** A token is valid until `ExpiredAt`, even if the user logged out or was deleted.
  The 15-minute TTL is the only bound. If you need immediate revocation, check the user against the
  gateway or your own store on each request rather than trusting the token alone.
- **No refresh handling.** Refresh tokens are redeemed only by this gateway. Do not attempt to
  verify one; you cannot, and you should not have it.
- **No claim beyond `role`.** Fine-grained permissions are your service's decision.

## Why two schemes

Refresh tokens stay `v2.local` (symmetric) because only this gateway ever issues *and* redeems them:
they travel as an `HttpOnly` cookie, are stored in Redis, and are rotated single-use. No third party
verifies them, so publishing a key for them would add key distribution with nothing in return.

Access tokens are the opposite case. Symmetric verification would mean handing every consuming
service the key that *creates* tokens — anyone able to check a token could forge an `admin` one. The
asymmetric split is what makes "other services can trust our tokens" possible without also making
them able to impersonate anyone.

## Key generation (operators)

The gateway reads `ACCESS_TOKEN_PRIVATE_KEY` as a hex-encoded 64-byte Ed25519 private key. Generate
one with:

```bash
go run ./cmd/keygen
```

Keep the private key out of version control — `.env` is gitignored. The public half is derived from
it at startup, so there is no second variable to keep in sync.

// Package pasetoauth lets a Go service verify PASETO v2.public access tokens
// issued by secure-auth-gateway, and gate its own HTTP routes on them,
// without importing a PASETO library or reimplementing verification.
package pasetoauth

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/o1egl/paseto/v2"
)

var (
	ErrExpiredToken = errors.New("the security token has expired")
	ErrInvalidToken = errors.New("invalid or tampered security token")
)

// TokenMeta carries the issued/expiry timestamps embedded in AccessTokenPayload.
type TokenMeta struct {
	IssuedAt  time.Time
	ExpiredAt time.Time
}

// Valid checks if the token is expired.
func (m *TokenMeta) Valid() error {
	if time.Now().After(m.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

// AccessTokenPayload is the claim shape signed into every access token. See
// docs/TOKEN_CONTRACT.md for the wire format.
type AccessTokenPayload struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	TokenMeta
}

// Verifier checks access token signatures using only the gateway's public
// key. It structurally cannot sign, so it is safe to build from a key
// fetched over the network (GET /.well-known/paseto-public-key).
type Verifier struct {
	paseto    *paseto.V2
	publicKey ed25519.PublicKey
}

// NewVerifier builds a Verifier from a 32-byte Ed25519 public key.
func NewVerifier(publicKey ed25519.PublicKey) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("access token public key must be exactly 32 bytes")
	}

	return &Verifier{
		paseto:    paseto.NewV2(),
		publicKey: publicKey,
	}, nil
}

// VerifyAccessToken checks the signature and then the expiry. paseto.Verify
// only proves authenticity, so the Valid() call below is what enforces TTL.
func (v *Verifier) VerifyAccessToken(token string) (*AccessTokenPayload, error) {
	var payload AccessTokenPayload

	if err := v.paseto.Verify(token, v.publicKey, &payload, nil); err != nil {
		return nil, ErrInvalidToken
	}

	if err := payload.Valid(); err != nil {
		return nil, err
	}

	return &payload, nil
}

// PublicKey returns the key this Verifier checks signatures against.
func (v *Verifier) PublicKey() ed25519.PublicKey {
	return v.publicKey
}

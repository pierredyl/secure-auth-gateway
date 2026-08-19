package auth

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/o1egl/paseto/v2"

	"secure-auth-gateway/pkg/pasetoauth"
)

var (
	ErrExpiredToken = errors.New("the security token has expired")
	ErrInvalidToken = errors.New("invalid or tampered security token")
)

// Metadata for tokens, embedded into token payload structs
type TokenMeta struct {
	IssuedAt  time.Time
	ExpiredAt time.Time
}

type RefreshTokenPayload struct {
	TokenID string `json:"token_id"`
	UserID  string `json:"user_id"`
	TokenMeta
}

// AccessTokenSigner holds the private key and is used to create access tokens.
type AccessTokenSigner struct {
	paseto     *paseto.V2
	privateKey ed25519.PrivateKey
}

// NewAccessTokenSigner takes a full 64-byte Ed25519 private key (seed + public
// key suffix), as produced by ed25519.GenerateKey or ed25519.NewKeyFromSeed.
func NewAccessTokenSigner(privateKey ed25519.PrivateKey) (*AccessTokenSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("access token private key must be exactly 64 bytes")
	}

	return &AccessTokenSigner{
		paseto:     paseto.NewV2(),
		privateKey: privateKey,
	}, nil
}

// CreateAccessToken signs a payload into a PASETO v2.public string. The claims
// are signed, not encrypted; any holder can read them.
func (s *AccessTokenSigner) CreateAccessToken(userID string, role string, duration time.Duration) (string, error) {
	payload := &pasetoauth.AccessTokenPayload{
		UserID: userID,
		Role:   role,
		TokenMeta: pasetoauth.TokenMeta{
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(duration),
		},
	}

	return s.paseto.Sign(s.privateKey, payload, nil)
}

// PublicKey returns the Ed25519 public key matching this signer.
func (s *AccessTokenSigner) PublicKey() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

// Verifier builds a signer that only knows the public key to verify tokens.
func (s *AccessTokenSigner) Verifier() *pasetoauth.Verifier {
	verifier, _ := pasetoauth.NewVerifier(s.PublicKey())
	return verifier
}

// RefreshTokenMaker issues and redeems refresh tokens as PASETO v2.local
// (symmetric). These never leave this service. They travel as an HttpOnly
// cookie and redeemed here so no third party needs to verify them
type RefreshTokenMaker struct {
	paseto *paseto.V2
	key    []byte
}

// NewRefreshTokenMaker only accepts symmetric keys with a length of 32 bytes.
func NewRefreshTokenMaker(key []byte) (*RefreshTokenMaker, error) {
	if len(key) != 32 {
		return nil, errors.New("symmetric key must be exactly 32 bytes")
	}

	return &RefreshTokenMaker{
		paseto: paseto.NewV2(),
		key:    key,
	}, nil
}

// CreateRefreshToken returns the token string and its ID, which is what gets
// stored in Redis for single-use rotation.
func (m *RefreshTokenMaker) CreateRefreshToken(userID string, duration time.Duration) (string, string, error) {
	tokenID := uuid.NewString()
	payload := &RefreshTokenPayload{
		TokenID: tokenID,
		UserID:  userID,
		TokenMeta: TokenMeta{
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(duration),
		},
	}
	token, err := m.paseto.Encrypt(m.key, payload, nil)
	return token, tokenID, err
}

func (m *RefreshTokenMaker) VerifyRefreshToken(token string) (*RefreshTokenPayload, error) {
	var payload RefreshTokenPayload

	err := m.paseto.Decrypt(token, m.key, &payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.TokenMeta.Valid()
	if err != nil {
		return nil, ErrExpiredToken
	}

	return &payload, nil
}

// Valid checks if the token is expired
func (payload *TokenMeta) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

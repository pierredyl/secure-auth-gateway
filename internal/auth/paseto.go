package auth

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/o1egl/paseto/v2"
)

var (
	ErrExpiredToken = errors.New("the security token has expired")
	ErrInvalidToken = errors.New("invalid or tampered security token")
)

type PasetoMaker struct {
	paseto *paseto.V2
	key    []byte
}

// NewPasetoMaker is a token worker that only accepts symmetric keys with a length of 32 bytes.
func NewPasetoMaker(key []byte) (*PasetoMaker, error) {
	if len(key) != 32 {
		return nil, errors.New("symmetric key must be exactly 32 bytes")
	}

	return &PasetoMaker{
		paseto: paseto.NewV2(),
		key:    key,
	}, nil

}

// AccessTokenPayload holds the data embedded inside a PASETO access token
type AccessTokenPayload struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

type RefreshTokenPayload struct {
	TokenID   string    `json:"token_id"`
	UserID    string    `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// CreateAccessToken takes a payload and encrypts it into a PASETO string.
func (m *PasetoMaker) CreateAccessToken(userID string, role string, duration time.Duration) (string, error) {
	payload := &AccessTokenPayload{
		UserID:    userID,
		Role:      role,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}

	return m.paseto.Encrypt(m.key, payload, nil)
}

// CreateRefreshToken creates a refresh token using the same PASETO flow
func (m *PasetoMaker) CreateRefreshToken(userID string, duration time.Duration) (string, error) {
	payload := &RefreshTokenPayload{
		TokenID:   uuid.NewString(),
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}

	return m.paseto.Encrypt(m.key, payload, nil)
}

// VerifyToken decrypts and validates a PASETO string
func (m *PasetoMaker) VerifyToken(token string) (*AccessTokenPayload, error) {
	var payload AccessTokenPayload

	err := m.paseto.Decrypt(token, m.key, &payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Check if the access token has expired
	if err := payload.Valid(); err != nil {
		if err == ErrExpiredToken {
			// Check if refresh token exists and valid
			// If there is a refresh token, issue a new access token, rotate the refresh token
			return nil, err
		}
		return nil, err
	}

	return &payload, nil
}

// Valid checks if the token is expired
func (payload *AccessTokenPayload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

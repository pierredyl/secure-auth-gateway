package auth

import (
	"errors"
	"time"

	"github.com/o1egl/paseto/v2"
)

var (
	ErrExpiredToken = errors.New("the security token has expired")
	ErrInvalidToken = errors.New("invalid or tampered security token")
)

// TokenPayload holds the data embedded inside a PASETO token
type TokenPayload struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

// Valid checks if the token is expired
func (payload *TokenPayload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

// NewPasetoMaker is a token worker that only accepts symmetric keys with a length of 32 bytes.
func NewPasetoMaker(symmetricKey []byte) (*PasetoMaker, error) {
	if len(symmetricKey) != 32 {
		return nil, errors.New("symmetric key must be exactly 32 bytes")
	}

	return &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: symmetricKey,
	}, nil

}

// CreateToken takes a payload and encrypts it into a PASETO string.
func (m *PasetoMaker) CreateToken(userID string, role string, duration time.Duration) (string, error) {
	payload := &TokenPayload{
		UserID:    userID,
		Role:      role,
		IssuedAt:  time.Time{},
		ExpiredAt: time.Now().Add(duration),
	}

	return m.paseto.Encrypt(m.symmetricKey, payload, nil)
}

// VerifyToken decrypts and validates a PASETO string
func (m *PasetoMaker) VerifyToken(token string) (*TokenPayload, error) {
	var payload TokenPayload

	err := m.paseto.Decrypt(token, m.symmetricKey, &payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if err := payload.Valid(); err != nil {
		return nil, err
	}

	return &payload, nil
}

/*
	Written by Dylan Pierre
	2026
	paseto_test.go tests logic for creating tokens and verifying them.
	This file ensures that tokens which are tampered with in any way
	will not pass verification.
*/

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"secure-auth-gateway/pkg/pasetoauth"
)

func newSigner(t *testing.T) *AccessTokenSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	signer, err := NewAccessTokenSigner(priv)
	if err != nil {
		t.Fatalf("NewAccessTokenSigner: %v", err)
	}
	return signer
}

func TestNewAccessTokenSignerRejectsWrongKeySize(t *testing.T) {
	if _, err := NewAccessTokenSigner(ed25519.PrivateKey(make([]byte, 32))); err == nil {
		t.Fatal("expected error for 32-byte private key, got nil")
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	signer := newSigner(t)

	token, err := signer.CreateAccessToken("user-123", "admin", time.Minute)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	payload, err := signer.Verifier().VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if payload.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", payload.UserID, "user-123")
	}
	if payload.Role != "admin" {
		t.Errorf("Role = %q, want %q", payload.Role, "admin")
	}
}

// A token signed by one key must not verify under an unrelated public key.
func TestAccessTokenRejectsForeignKey(t *testing.T) {
	token, err := newSigner(t).CreateAccessToken("user-123", "admin", time.Minute)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	if _, err := newSigner(t).Verifier().VerifyAccessToken(token); !errors.Is(err, pasetoauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken from a foreign key, got %v", err)
	}
}

func TestAccessTokenRejectsTamperedToken(t *testing.T) {
	signer := newSigner(t)
	token, err := signer.CreateAccessToken("user-123", "user", time.Minute)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	tampered := []byte(token)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := signer.Verifier().VerifyAccessToken(string(tampered)); !errors.Is(err, pasetoauth.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken from a tampered token, got %v", err)
	}
}

func TestAccessTokenRejectsExpiredToken(t *testing.T) {
	signer := newSigner(t)

	token, err := signer.CreateAccessToken("user-123", "user", -time.Second)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	if _, err := signer.Verifier().VerifyAccessToken(token); !errors.Is(err, pasetoauth.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestPublicKeyMatchesSigner(t *testing.T) {
	signer := newSigner(t)

	verifier, err := pasetoauth.NewVerifier(signer.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := signer.CreateAccessToken("user-123", "user", time.Minute)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	if _, err := verifier.VerifyAccessToken(token); err != nil {
		t.Fatalf("a verifier built from PublicKey() must accept the signer's tokens, got %v", err)
	}
}

func TestNewRefreshTokenMakerRejectsWrongKeySize(t *testing.T) {
	if _, err := NewRefreshTokenMaker(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte symmetric key, got nil")
	}
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	maker, err := NewRefreshTokenMaker(key)
	if err != nil {
		t.Fatalf("NewRefreshTokenMaker: %v", err)
	}

	token, tokenID, err := maker.CreateRefreshToken("user-123", time.Minute)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	payload, err := maker.VerifyRefreshToken(token)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}
	if payload.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", payload.UserID, "user-123")
	}
	if payload.TokenID != tokenID {
		t.Errorf("TokenID = %q, want %q", payload.TokenID, tokenID)
	}
}

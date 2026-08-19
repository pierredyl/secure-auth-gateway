package pasetoauth

import (
	"crypto/ed25519"
	"testing"
)

func TestNewVerifierRejectsWrongKeySize(t *testing.T) {
	if _, err := NewVerifier(ed25519.PublicKey(make([]byte, 64))); err == nil {
		t.Fatal("expected error for 64-byte public key, got nil")
	}
}

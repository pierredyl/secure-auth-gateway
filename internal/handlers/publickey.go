package handlers

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// PublicKeyResponse is the contract other services depend on to verify our
// access tokens. Fields are named rather than raw bytes so a consumer can tell
// which algorithm to use without guessing.
type PublicKeyResponse struct {
	Algorithm     string `json:"algorithm"`
	PasetoVersion string `json:"paseto_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
}

// PublicKeyHandler serves the Ed25519 public key for access token verification.
// It takes the raw key, not a verifier, so it cannot reach signing material.
// The body is built once — rotating the key would require a restart.
func PublicKeyHandler(publicKey ed25519.PublicKey) http.HandlerFunc {
	body, err := json.Marshal(PublicKeyResponse{
		Algorithm:     "ed25519",
		PasetoVersion: "v2.public",
		KeyID:         "access-token-v1",
		PublicKey:     hex.EncodeToString(publicKey),
	})
	if err != nil {
		panic("failed to marshal public key response: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

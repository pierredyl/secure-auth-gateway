// Command verify-token independently verifies an access token issued by the
// secure-auth-gateway, using nothing but the service's published public key.
//
// It deliberately imports no packages from the gateway itself — this is what a
// third-party service written against the token contract would look like.
//
// Usage:
//
//	go run . <base-url> <access-token>
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/o1egl/paseto/v2"
)

// publicKeyResponse mirrors GET /.well-known/paseto-public-key
type publicKeyResponse struct {
	Algorithm     string `json:"algorithm"`
	PasetoVersion string `json:"paseto_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
}

// accessTokenPayload mirrors the gateway's access token claims. IssuedAt and
// ExpiredAt carry no json tags on the gateway side, so they serialize under
// their Go field names.
type accessTokenPayload struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"IssuedAt"`
	ExpiredAt time.Time `json:"ExpiredAt"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verify-token <base-url> <access-token>")
		os.Exit(2)
	}
	baseURL, token := os.Args[1], os.Args[2]

	publicKey, err := fetchPublicKey(baseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not fetch public key: %v\n", err)
		os.Exit(1)
	}

	var payload accessTokenPayload
	if err := paseto.NewV2().Verify(token, publicKey, &payload, nil); err != nil {
		fmt.Fprintf(os.Stderr, "SIGNATURE INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("signature OK — token was issued by the holder of the matching private key")

	// Verify() only proves authenticity. Expiry is the caller's job.
	if time.Now().After(payload.ExpiredAt) {
		fmt.Fprintf(os.Stderr, "TOKEN EXPIRED at %s\n", payload.ExpiredAt.Format(time.RFC3339))
		os.Exit(1)
	}
	fmt.Printf("not expired — %s remaining\n\n", time.Until(payload.ExpiredAt).Round(time.Second))

	claims, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not format claims: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("claims:\n%s\n", claims)
}

func fetchPublicKey(baseURL string) (ed25519.PublicKey, error) {
	resp, err := http.Get(baseURL + "/.well-known/paseto-public-key")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	var body publicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	if body.Algorithm != "ed25519" || body.PasetoVersion != "v2.public" {
		return nil, fmt.Errorf("unsupported key: algorithm=%q version=%q", body.Algorithm, body.PasetoVersion)
	}

	key, err := hex.DecodeString(body.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid hex: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}

	fmt.Printf("fetched public key %s (%s, %s)\n", body.KeyID, body.Algorithm, body.PasetoVersion)
	return ed25519.PublicKey(key), nil
}

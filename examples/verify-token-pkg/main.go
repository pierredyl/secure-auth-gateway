// Command verify-token-pkg verifies an access token issued by
// secure-auth-gateway using the gateway's own pkg/pasetoauth package instead
// of hand-rolling verification against the raw PASETO library.
//
// Compare this to examples/verify-token, which shows the same thing done by
// hand for consumers who can't or don't want to import this module.
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

	"secure-auth-gateway/pkg/pasetoauth"
)

// publicKeyResponse mirrors GET /.well-known/paseto-public-key
type publicKeyResponse struct {
	Algorithm     string `json:"algorithm"`
	PasetoVersion string `json:"paseto_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verify-token-pkg <base-url> <access-token>")
		os.Exit(2)
	}
	baseURL, token := os.Args[1], os.Args[2]

	publicKey, err := fetchPublicKey(baseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not fetch public key: %v\n", err)
		os.Exit(1)
	}

	verifier, err := pasetoauth.NewVerifier(publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build verifier: %v\n", err)
		os.Exit(1)
	}

	// One call does what examples/verify-token does by hand: checks the
	// signature and the expiry.
	payload, err := verifier.VerifyAccessToken(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TOKEN REJECTED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("token accepted")
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

	fmt.Printf("fetched public key %s (%s, %s)\n", body.KeyID, body.Algorithm, body.PasetoVersion)
	return ed25519.PublicKey(key), nil
}

// Written by Dylan Pierre
// 2026
// Command keygen prints a fresh set of token keys for a .env file.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generating ed25519 keypair: %v", err)
	}

	refreshKey := make([]byte, 32)
	if _, err := rand.Read(refreshKey); err != nil {
		log.Fatalf("generating refresh key: %v", err)
	}

	fmt.Printf("ACCESS_TOKEN_PRIVATE_KEY=%s\n", hex.EncodeToString(priv))
	fmt.Printf("REFRESH_TOKEN_KEY=%s\n", hex.EncodeToString(refreshKey))
	fmt.Printf("\n# public key, derived at startup — published at /.well-known/paseto-public-key\n")
	fmt.Printf("# %s\n", hex.EncodeToString(pub))
}

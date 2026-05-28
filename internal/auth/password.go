package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// OWASP 2026 recommended minimum parameters for Argon2id crypto
// Allows for scaling by tuning these parameters to fit security needs
const (
	Argon2Time        = 2         // Time cost (CPU time to calculate hash)
	Argon2Memory      = 19 * 1024 // Roughly 19MB Memory Cost (per password guess)
	Argon2Parallelism = 1         // CPU Threads (allow only one)
	SaltLength        = 16        // Salt Size (16 bytes -> 128 bits of entropy)
	KeyLength         = 32        // Length of output hash (32 bytes -> 256 bit hash, collision practically impossible)
)

var ErrInvalidHashFormat = errors.New("the stored hash does not match the expected argon2id format")

/*
HashPassword takes a plaintext password and returns a fully encoded modular crypt string.
It first generates a 'random' salt using a CSPRNG over PRNG to guarantee a random seed.
Then it computes the digest, encodes the salt and digest to base64, and returns a string
containing the configuration parameters for the algorithm.
*/
func HashPassword(password string) (string, error) {
	// Generate a cryptographically secure random salt using crypto/rand
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Argon2id hash digest
	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Parallelism, KeyLength)

	// Base64 representations of the salt and hash digest
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// encoded is a string containing all configuration parameters
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, Argon2Memory, Argon2Time, Argon2Parallelism, b64Salt, b64Hash)

	return encoded, nil
}

/*
VerifyPassword takes in a cleartext password, and an encodedHash string.
This encodedHash string contains configuration parameters for argon2 version, memory,
time, parallelism, the base64 salt, and a base64 previously computed digest.
*/
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Split the encoded hash string to its parts
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHashFormat
	}

	var version int
	var memory, timeCost uint32
	var parallelism uint8

	// Parse version
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("argon2 versions don't match")
	}

	// Parse performance tuning parameters
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
		return false, err
	}

	// Extract, decode the salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	// Extract, decode the original hash digest
	originalHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	// Compute the hash of incoming password with identical parameters.
	comparisonHash := argon2.IDKey([]byte(password), salt, timeCost, memory, parallelism, uint32(len(originalHash)))

	// Using a constant-time comparison to prevent timing attacks.
	// Time can't be abused as a method of similarity.
	if subtle.ConstantTimeCompare(originalHash, comparisonHash) == 1 {
		return true, nil
	}

	return false, nil
}

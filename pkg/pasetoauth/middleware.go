package pasetoauth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

// UserPayloadKey is the context key AuthenticateToken stores the verified
// *AccessTokenPayload under.
const UserPayloadKey contextKey = "user_payload"

// AuthenticateToken returns middleware that rejects requests without a valid
// "Authorization: Bearer <token>" header, and otherwise stores the verified
// token's payload in the request context under UserPayloadKey.
func AuthenticateToken(verifier *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			if authHeader == "" {
				http.Error(w, `{"error": "Missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			fields := strings.Fields(authHeader)
			if len(fields) < 2 || strings.ToLower(fields[0]) != "bearer" {
				http.Error(w, `{"error": "Invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			token := fields[1]
			payload, err := verifier.VerifyAccessToken(token)
			if err != nil {
				http.Error(w, `{"error": "Unauthorized: invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserPayloadKey, payload)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

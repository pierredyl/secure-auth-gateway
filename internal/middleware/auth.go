package middleware

import (
	"context"
	"net/http"
	"secure-auth-gateway/internal/auth"
	"strings"
)

type contextKey string

const UserPayloadKey contextKey = "user_payload"

func AuthMiddleware(maker *auth.PasetoMaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Grab the authorization header
			authHeader := r.Header.Get("Authorization")

			// Check if header exists
			if authHeader == "" {
				http.Error(w, `{"error": "Missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expecting format "Bearer <token>"
			fields := strings.Fields(authHeader)
			if len(fields) < 2 || strings.ToLower(fields[0]) != "bearer" {
				http.Error(w, `{"error": "Invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			token := fields[1]
			payload, err := maker.VerifyToken(token)
			if err != nil {
				http.Error(w, `{"error": "Unauthorized: invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserPayloadKey, payload)
			next.ServeHTTP(w, r.WithContext(ctx))

		})
	}
}

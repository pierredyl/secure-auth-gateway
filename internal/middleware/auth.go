package middleware

import (
	"context"
	"net/http"
	"net/netip"
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

			// Grab the current incoming request's IP address
			currentIP := r.RemoteAddr
			if forwardedIP := r.Header.Get("X-Forwarded-For"); forwardedIP != "" {
				currentIP = forwardedIP
			}

			issuedAddr, _ := netip.ParseAddr(payload.IssuedIP)
			currentAddr, _ := netip.ParseAddr(currentIP)

			// If the current IP doesn't match the IP embedded in the token
			if issuedAddr != currentAddr {
				http.Error(w, "Unauthorized: Token context mismatch: different IPs", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserPayloadKey, payload)
			next.ServeHTTP(w, r.WithContext(ctx))

		})
	}
}

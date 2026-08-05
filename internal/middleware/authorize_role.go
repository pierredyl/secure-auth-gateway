package middleware

import (
	"net/http"
	"secure-auth-gateway/internal/auth"
)

func RequireRole(allowedRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			val := r.Context().Value(UserPayloadKey)
			if val == nil {
				http.Error(w, `{"error": "Unauthorized: No user context found"}`, http.StatusUnauthorized)
				return
			}

			userPayload := val.(*auth.TokenPayload)

			if userPayload.Role != allowedRole {
				http.Error(w, `{"error": "Forbidden: Insufficient permissions"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

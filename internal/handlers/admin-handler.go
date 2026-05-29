package handlers

import (
	"encoding/json"
	"net/http"
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/middleware"
)

func AdminDashboard(w http.ResponseWriter, r *http.Request) {
	payload, ok := r.Context().Value(middleware.UserPayloadKey).(*auth.TokenPayload)

	// Demonstrating Defense in depth. AuthMiddleware ran, so this should be okay,
	// but this is another check to fail closed
	if !ok {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome to the Admin dashboard",
		"userID":  payload.UserID,
		"role":    payload.Role,
	})
}

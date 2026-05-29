package handlers

import (
	"encoding/json"
	"net/http"
	"secure-auth-gateway/internal/auth"
	"time"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// Password 15 characters minimum to match NIST standards. Max is 72 for Bcrypt algorithm.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=15,max=72"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type IdentityStore interface {
	VerifyUserCredentials(email, password string) (userID string, role string, err error)
}

type AuthHandler struct {
	tokenMaker *auth.PasetoMaker
	db         IdentityStore
}

func NewAuthHandler(tokenMaker *auth.PasetoMaker, db IdentityStore) *AuthHandler {
	return &AuthHandler{
		tokenMaker: tokenMaker,
		db:         db,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	// Check for broken JSON data
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Malformed JSON payload"}`, http.StatusBadRequest)
		return
	}

	// Validate struct constraints
	if err := validate.Struct(req); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Validation failed: Email must be valid, Password must be 15-72 characters.",
		})
		return
	}

	// Securely hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error": "Internal Security Error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"email":       req.Email,
		"stored_hash": hashedPassword})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	// Check valid JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Malformed JSON payload"}`, http.StatusBadRequest)
		return
	}

	// Validate struct contraints
	if err := validate.Struct(req); err != nil {
		http.Error(w, `{"error": "Invalid input formatting"}`, http.StatusBadRequest)
		return
	}

	// Grab userID and role from external database
	userID, role, err := h.db.VerifyUserCredentials(req.Email, req.Password)
	if err != nil {
		http.Error(w, `{"error:" "Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// Also grab the IP
	clientIP := r.RemoteAddr

	// If gateway is behind a proxy
	if forwardedIP := r.Header.Get("X-Fowarded-For"); forwardedIP != "" {
		clientIP = forwardedIP
	}

	// Create token for that user and role
	token, err := h.tokenMaker.CreateToken(userID, role, 15*time.Minute, clientIP)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Return token
	json.NewEncoder(w).Encode(map[string]string{
		"userID":       userID,
		"role":         role,
		"access_token": token,
	})
}

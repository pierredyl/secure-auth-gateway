package handlers

import (
	"encoding/json"
	"log"
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

type AuthHandler struct{}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
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
		"message":     "Registration pre-validation succesful",
		"stored_hash": hashedPassword})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Only included in dev
	superSecretKey := []byte("0123456789abcdef0123456789abcdef")

	tokenMaker, err := auth.NewPasetoMaker(superSecretKey)
	if err != nil {
		log.Fatalf("Failed to creat PASETO token maker: %v", err)
	}

	// Verifying email + password would be here
	// If that succeeds, issue a token

	// Simulate issuing a token for "user_test", as an admin, and 15 minutes
	token, err := tokenMaker.CreateToken("user_test", "admin", 15*time.Minute)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"access_token": token,
		"message": "User recieves token, authed and authorized to resources"})
}

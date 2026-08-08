package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"secure-auth-gateway/internal/auth"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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

type UserResponse struct {
	ID           uuid.UUID `json:"id"`
	Role         string    `json:"role"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuthHandler struct {
	tokenMaker *auth.PasetoMaker
	DB         *pgxpool.Pool
}

func NewAuthHandler(tokenMaker *auth.PasetoMaker, DB *pgxpool.Pool) *AuthHandler {
	return &AuthHandler{
		tokenMaker: tokenMaker,
		DB:         DB,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	query := ``

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

	var exists int
	// Query the database to check if user exists before hashing password
	query = `
		SELECT 1 FROM users WHERE email = $1
	`

	err := h.DB.QueryRow(r.Context(), query, req.Email).Scan(&exists)
	// If there is no error, email was found
	if err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email already registered"})
		return
	}

	// If there is some error not related to email not found
	if !errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Securely hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error": "Internal Security Error"}`, http.StatusInternalServerError)
		return
	}

	// Create the query
	query = `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, created_at
	`
	var resp UserResponse
	// Run the query in the database
	err = h.DB.QueryRow(r.Context(), query, req.Email, hashedPassword).
		Scan(&resp.ID, &resp.Email, &resp.CreatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "Email already registered"})
			return
		}
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
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

	// Grab user information from the database by their email
	query := `
		SELECT id, email, password_hash, created_at, role
		FROM users
		WHERE email = $1
	`
	var resp UserResponse
	err := h.DB.QueryRow(r.Context(), query, req.Email).
		Scan(&resp.ID, &resp.Email, &resp.PasswordHash, &resp.CreatedAt, &resp.Role)

	// Email didn't match any in the DB
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// deliberately vague — see note below
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid email or password"})
			return
		}
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Verify the hashstring
	ok, err := auth.VerifyPassword(req.Password, resp.PasswordHash)
	if err != nil || !ok {
		http.Error(w, `{"error": "Forbidden."}`, http.StatusUnauthorized)
		return
	}

	// Create token for that user and role
	token, err := h.tokenMaker.CreateToken(resp.ID.String(), resp.Role, 15*time.Minute)
	if err != nil {
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,                    // JS cannot read this cookie — mitigates XSS token theft
		Secure:   false,                   // only sent over HTTPS (disable for local http:// dev)
		SameSite: http.SameSiteStrictMode, // mitigates CSRF
		Expires:  time.Now().Add(15 * time.Minute),
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id":    resp.ID,
		"email": resp.Email,
	})
}

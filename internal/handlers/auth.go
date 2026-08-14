package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/redis_db"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// dummyHash is verified against when the email doesn't exist, so an unknown
// address costs the same wall-clock time as a wrong password. Without it, the
// response time alone tells an attacker which accounts are real.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := auth.HashPassword("dummy-password-for-constant-time-login")
	if err != nil {
		log.Fatalf("Failed to precompute the login dummy hash: %v", err)
	}
	return h
}

// respondInvalidCredentials is the single response for every failed login. Both
// callers must stay byte-identical — a difference in status, body, or headers is
// an email enumeration oracle.
func respondInvalidCredentials(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "Invalid email or password"})
}

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
	ID        uuid.UUID `json:"id"`
	Role      string    `json:"role"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type AuthHandler struct {
	accessTokenMaker  *auth.PasetoMaker
	refreshTokenMaker *auth.PasetoMaker
	redisClient       *redis.Client
	DB                *pgxpool.Pool
}

func NewAuthHandler(accessTokenMaker *auth.PasetoMaker, refreshTokenMaker *auth.PasetoMaker, redisClient *redis.Client, DB *pgxpool.Pool) *AuthHandler {
	return &AuthHandler{
		accessTokenMaker:  accessTokenMaker,
		refreshTokenMaker: refreshTokenMaker,
		redisClient:       redisClient,
		DB:                DB,
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
		log.Printf("register: user existence check failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Securely hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("register: password hashing failed: %v", err)
		http.Error(w, `{"error": "Internal Security Error"}`, http.StatusInternalServerError)
		return
	}

	// Create the query
	query = `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, created_at, role
	`
	var resp UserResponse
	// Run the query in the database
	err = h.DB.QueryRow(r.Context(), query, req.Email, hashedPassword).
		Scan(&resp.ID, &resp.Email, &resp.CreatedAt, &resp.Role)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "Email already registered"})
			return
		}
		log.Printf("register: insert failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "User successfully registered.",
		"data":    resp,
	})
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

	// Check if the user account is locked before quering the DB
	if locked, retryAfter := redis_db.IsLocked(r.Context(), req.Email); locked {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "Too many failed attempts. Try again later."})
		return
	}

	// Grab user information from the database by their email
	query := `
		SELECT id, email, password_hash, created_at, role
		FROM users
		WHERE email = $1
	`
	var resp UserResponse
	var passwordHash string
	err := h.DB.QueryRow(r.Context(), query, req.Email).
		Scan(&resp.ID, &resp.Email, &passwordHash, &resp.CreatedAt, &resp.Role)

	// Email didn't match any in the DB
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Burn the same time a real verification would take before answering.
			auth.VerifyPassword(req.Password, dummyHash)
			redis_db.RecordFailure(r.Context(), req.Email)
			respondInvalidCredentials(w)
			return
		}
		log.Printf("login: user lookup failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Verify the hashstring
	ok, err := auth.VerifyPassword(req.Password, passwordHash)
	if err != nil || !ok {
		redis_db.RecordFailure(r.Context(), req.Email)
		respondInvalidCredentials(w)
		return
	}

	redis_db.ResetFailures(r.Context(), req.Email)

	// Create a new access token for that user and role
	accessToken, err := h.accessTokenMaker.CreateAccessToken(resp.ID.String(), resp.Role, 15*time.Minute)
	if err != nil {
		log.Printf("login: access token creation failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Create a new refresh token for that user
	refreshToken, tokenID, err := h.refreshTokenMaker.CreateRefreshToken(resp.ID.String(), 30*24*time.Hour)
	if err != nil {
		log.Printf("login: refresh token creation failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Return refresh token as HTTP cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/api/v1/auth",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// redis SET command: SET refresh[id] [userid] 30 days
	if err := h.redisClient.Set(r.Context(), "refresh:"+tokenID, resp.ID.String(), 30*24*time.Hour).Err(); err != nil {
		log.Printf("login: redis Set failed for refresh token: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Return access token in JSON response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message":      "User successfully logged in.",
		"access_token": accessToken,
	})
}

/*
func (*AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {

}
*/

// respondInvalidSession is the single response for every failed refresh check
// (missing/invalid/expired/reused token, userID mismatch). Collapsing these
// into one message avoids exposing which specific check failed.
func respondInvalidSession(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired refresh session"})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Read the cookie with the refresh token
	refresh_token, err := r.Cookie("refresh_token")
	if err != nil {
		log.Printf("refresh: no refresh_token cookie: %v", err)
		respondInvalidSession(w)
		return
	}

	// Extract the payload inside of the refresh token and check expiry
	payload, err := h.refreshTokenMaker.VerifyRefreshToken(refresh_token.Value)
	if err != nil {
		log.Printf("refresh: token verification failed: %v", err)
		respondInvalidSession(w)
		return
	}

	// Atomically claim and invalidate the stored token (single-use rotation)
	userID, err := h.redisClient.GetDel(r.Context(), "refresh:"+payload.TokenID).Result()
	if err != nil {
		if err == redis.Nil {
			log.Printf("refresh: token %s not found in redis (already used or expired)", payload.TokenID)
		} else {
			log.Printf("refresh: redis GetDel error: %v", err)
		}
		respondInvalidSession(w)
		return
	}

	// Check userID if it matches
	if userID != payload.UserID {
		log.Printf("refresh: userID mismatch for token %s: redis=%s payload=%s", payload.TokenID, userID, payload.UserID)
		respondInvalidSession(w)
		return
	}

	// Get the users role for their new access token from the DB
	query := `SELECT role FROM users WHERE id = $1`
	var role string

	err = h.DB.QueryRow(r.Context(), query, payload.UserID).Scan(&role)
	if err != nil {
		log.Printf("refresh: role lookup failed for user %s: %v", payload.UserID, err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Create their new access token
	accessToken, err := h.accessTokenMaker.CreateAccessToken(payload.UserID, role, 15*time.Minute)
	if err != nil {
		log.Printf("refresh: access token creation failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Rotate the refresh token
	remaining_time_refresh_token := time.Until(payload.ExpiredAt)
	new_refresh_token, new_refresh_token_ID, err := h.refreshTokenMaker.CreateRefreshToken(payload.UserID, remaining_time_refresh_token)
	if err != nil {
		log.Printf("refresh: refresh token creation failed: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Set the new refresh token
	if err := h.redisClient.Set(r.Context(), "refresh:"+new_refresh_token_ID, payload.UserID, remaining_time_refresh_token).Err(); err != nil {
		log.Printf("refresh: redis Set failed for new token: %v", err)
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Return refresh token as HTTP cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    new_refresh_token,
		Path:     "/api/v1/auth",
		Expires:  time.Now().Add(remaining_time_refresh_token),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Return access token in JSON response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message":      "Access token refreshed.",
		"access_token": accessToken,
	})
}

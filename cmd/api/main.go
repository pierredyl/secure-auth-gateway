package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/handlers"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	//Start the token maker
	superSecretKey := []byte("0123456789abcdef0123456789abcdef")
	tokenMaker, err := auth.NewPasetoMaker(superSecretKey)
	if err != nil {
		log.Fatalf("Failed to create the PASETO token maker")
	}

	// Local testing database
	mockDB := &LocalTestDB{}

	// Register secure routes
	handlers.RegisterSecureRoutes(r, tokenMaker, mockDB, func(
		admin chi.Router,
		user chi.Router,
		biling chi.Router,
		support chi.Router) {

		admin.Get("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "success", "data": "Cargo manifests loaded."}`))
		})
	})

	//Start the server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("Secure Auth Gateway running on port 8080...")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}

// ─── TEMPORARY MOCK DATABASE FOR TESTING ─────────────────────────────────────
type LocalTestDB struct{}

func (m *LocalTestDB) VerifyUserCredentials(email, password string) (string, string, error) {
	// a dummy admin account for testing
	if email == "admin@test.com" && password == "SuperSecurePassword123" {
		return "user_abc123", "admin", nil
	}

	// a dummy standard user account for testing role restrictions
	if email == "user@test.com" && password == "AnotherSecurePassword123" {
		return "user_xyz789", "user", nil
	}

	// Return an error if they pass wrong credentials
	return "", "", errors.New("invalid email or password")
}

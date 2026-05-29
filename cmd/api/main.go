package main

import (
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
		support chi.Router,
		billing chi.Router) {

		admin.Get("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "success", "data": "Dashboard loaded."}`))
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

func (m *LocalTestDB) GrabUserInformation(email string) (userID, role, passwordHash string, err error) {
	return
}

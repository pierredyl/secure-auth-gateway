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
	mockDB := &MockDB{}

	handlers.RegisterSecureRoutes(r, tokenMaker, mockDB)

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

type MockDB struct {
}

func (m *MockDB) GrabUserInformation(email string) (userID, role, passwordHash string, err error) {
	if email == "admin@test.com" {
		return "user_1", "admin", "$argon2id$v=19$m=19456,t=2,p=1$esBiVmzhQZE7NcN1t5EGXw$F3G/HYUIF+BtADQxq4e0bM01Ya+/vK8aHJUXzoG0Qa8", nil
	}
	return "", "", "", errors.New("user not fond")
}

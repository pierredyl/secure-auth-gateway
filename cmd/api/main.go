package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/database"
	"secure-auth-gateway/internal/handlers"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	// Create the router
	r := chi.NewRouter()

	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load .env file")
	}
	fmt.Println(".env file loaded successfully")

	// Start the token maker
	key := os.Getenv("KEY")
	keyBytes := []byte(key)
	tokenMaker, err := auth.NewPasetoMaker(keyBytes)
	if err != nil {
		log.Fatalf("Failed to create the PASETO token maker")
	}
	fmt.Println("PASETO Token Maker initialized successfully")

	// Connect to Postgres Database
	context := context.Background()
	if err := database.Connect(context); err != nil {
		log.Fatalf("Failed to connect to Postgres")
	}
	fmt.Println("Connected to Postgres Database")
	defer database.Pool.Close()

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

func (m *MockDB) CreateUser(email, hashedPassword string) (err error) {
	return
}

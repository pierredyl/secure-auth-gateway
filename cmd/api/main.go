package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"secure-auth-gateway/internal/auth"
	database "secure-auth-gateway/internal/db"
	"secure-auth-gateway/internal/handlers"
	"time"

	"secure-auth-gateway/internal/ratelimit"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	// Create the router
	r := chi.NewRouter()

	// Load the .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	} else {
		fmt.Println(".env file loaded successfully")
	}

	// Start the token maker
	key := os.Getenv("KEY")
	keyBytes, err := hex.DecodeString(key)
	tokenMaker, err := auth.NewPasetoMaker(keyBytes)
	if err != nil {
		log.Fatalf("Failed to create the PASETO token maker")
	}
	fmt.Println("PASETO Token Maker initialized successfully")

	// Connect to Postgres Database
	ctx := context.Background()
	if err := database.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect to Postgres")
	}
	fmt.Println("Connected to Postgres Database")
	defer database.Pool.Close()

	// Run DB Migrations
	if err := database.RunMigrations(os.Getenv("DATABASE_URL")); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	fmt.Println("Migrations applied successfully")

	// Connect to Redis
	if err := ratelimit.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect to Redis")
	}
	fmt.Println("Connected to Redis")

	// Start the AuthHandler
	authHandler := handlers.NewAuthHandler(tokenMaker, database.Pool)
	fmt.Println("AuthHandler started")

	// Register the available API Routes
	handlers.RegisterSecureRoutes(r, tokenMaker, authHandler)

	//Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("Secure Auth Gateway running on port " + port + "...")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}

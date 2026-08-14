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
	"secure-auth-gateway/internal/redis_db"
	"time"

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

	// Start the token makers
	access_token_key := os.Getenv("ACCESS_TOKEN_KEY")

	access_token_key_bytes, err := hex.DecodeString(access_token_key)
	if err != nil {
		log.Fatalf("Failed to decode string")
	}

	accessTokenMaker, err := auth.NewPasetoMaker(access_token_key_bytes)
	if err != nil {
		log.Fatalf("Failed to create the PASETO access token maker")
	}
	fmt.Println("PASETO Access Token Maker initialized successfully")

	// Refresh token
	refresh_token_key := os.Getenv("REFRESH_TOKEN_KEY")

	refresh_token_key_bytes, err := hex.DecodeString(refresh_token_key)
	if err != nil {
		log.Fatalf("Failed to decode string")
	}

	refreshTokenMaker, err := auth.NewPasetoMaker(refresh_token_key_bytes)
	if err != nil {
		log.Fatalf("Failed to create the PASETO refresh token maker")
	}
	fmt.Println("PASETO Refresh Token Maker initialized successfully")

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
	if err := redis_db.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect to Redis")
	}
	fmt.Println("Connected to Redis")

	// Start the AuthHandler
	authHandler := handlers.NewAuthHandler(accessTokenMaker, refreshTokenMaker, redis_db.Client, database.Pool)
	fmt.Println("AuthHandler started")

	// Register the available API Routes
	handlers.RegisterSecureRoutes(r, accessTokenMaker, refreshTokenMaker, authHandler)

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

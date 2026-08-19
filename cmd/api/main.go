// Written by Dylan Pierre
// 2026
/*
	Main is the entryway into the program. Loads the router,
	starts the token makers, connects to Redis, and to Postgres.
	HTTP Requests are routed here.
*/

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // registers profiling handlers on http.DefaultServeMux
	"os"
	"os/signal"
	"secure-auth-gateway/internal/auth"
	database "secure-auth-gateway/internal/db"
	"secure-auth-gateway/internal/handlers"
	"secure-auth-gateway/internal/redis_db"
	"syscall"
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
	access_token_private_key := os.Getenv("ACCESS_TOKEN_PRIVATE_KEY")

	access_token_private_key_bytes, err := hex.DecodeString(access_token_private_key)
	if err != nil {
		log.Fatalf("Failed to decode ACCESS_TOKEN_PRIVATE_KEY")
	}

	accessTokenSigner, err := auth.NewAccessTokenSigner(ed25519.PrivateKey(access_token_private_key_bytes))
	if err != nil {
		log.Fatalf("Failed to create the PASETO access token signer: %v", err)
	}
	fmt.Println("PASETO Access Token Signer initialized successfully")

	// Refresh token
	refresh_token_key := os.Getenv("REFRESH_TOKEN_KEY")

	refresh_token_key_bytes, err := hex.DecodeString(refresh_token_key)
	if err != nil {
		log.Fatalf("Failed to decode string")
	}

	refreshTokenMaker, err := auth.NewRefreshTokenMaker(refresh_token_key_bytes)
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
	// Closed explicitly after a graceful shutdown below, not deferred here: the
	// server's only current exit path on a startup failure is log.Fatal, which
	// calls os.Exit and skips every deferred function — a defer this early would
	// never actually run on that path anyway.

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
	authHandler := handlers.NewAuthHandler(accessTokenSigner, refreshTokenMaker, redis_db.Client, database.Pool)
	fmt.Println("AuthHandler started")

	// Register the available API Routes
	handlers.RegisterSecureRoutes(r, authHandler)

	//Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Profiling endpoints, deliberately on their own listener and their own mux.
	//
	// They must NOT go on the chi router: nginx proxies "location /", so anything
	// mounted there is reachable from the public port, and /debug/pprof/heap on a
	// service that handles password hashes is a serious disclosure. Port 6060 is
	// not published in docker-compose.yml either — reach it with
	// `docker compose exec app1 wget -qO- localhost:6060/debug/pprof/`.
	//
	// The blank import registers the handlers on http.DefaultServeMux, which is
	// why this passes nil rather than r.
	go func() {
		log.Println("pprof listening on :6060 (private, not proxied)")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Printf("pprof listener stopped: %v", err)
		}
	}()

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ListenAndServe blocks the calling goroutine until the server stops, so it
	// runs on its own goroutine here — that's what leaves the main goroutine free
	// to wait on the shutdown signal below and call srv.Shutdown while the accept
	// loop is still running. Shutdown has no other way to reach a live server.
	serverErr := make(chan error, 1)
	go func() {
		log.Println("Secure Auth Gateway running on port " + port + "...")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		log.Fatalf("server failed: %v", err)
	case <-ctx.Done():
		log.Println("shutdown signal received, draining in-flight requests...")
	}

	// 10 Seconds for in process requests to finish
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown did not complete in time: %v", err)
	}

	database.Pool.Close()
	log.Println("shutdown complete")
}

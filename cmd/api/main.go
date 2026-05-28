package main

import (
	"log"
	"net/http"
	"time"

	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/handlers"
	"secure-auth-gateway/internal/middleware"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
)

func main() {
	// Router
	r := chi.NewRouter()

	// Middleware on the router
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.SecurityHeaders)

	//Start the handlers
	authHandler := handlers.NewAuthHandler()
	adminHandler := handlers.NewAdminHandler()

	//Start the token maker
	superSecretKey := []byte("0123456789abcdef0123456789abcdef")
	tokenMaker, err := auth.NewPasetoMaker(superSecretKey)
	if err != nil {
		log.Fatalf("Failed to create the PASETO token maker")
	}

	// 1. Public Route group
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// 2. Admin group
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(tokenMaker))
		r.Use(middleware.RequireRole("admin"))

		r.Get("/api/v1/admin/dashboard", adminHandler.Dashboard)
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

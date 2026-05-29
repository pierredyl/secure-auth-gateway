package handlers

import (
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/middleware"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

func RegisterSecureRoutes(r chi.Router, tokenMaker *auth.PasetoMaker, db IdentityStore) {
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.SecurityHeaders)

	authHandler := NewAuthHandler(tokenMaker, db)

	// Public: rate-limited, no auth required.
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(httprate.Limit(5, 1*time.Minute, httprate.WithKeyFuncs(httprate.KeyByIP)))
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// Protected: every route past here requires a valid token.
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(tokenMaker))

		// Admin-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("admin"))
			r.Get("/api/v1/admin/dashboard", AdminDashboard)
		})

		// User-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("user"))
			r.Get("/api/v1/user/profile", UserProfile)
		})
	})
}

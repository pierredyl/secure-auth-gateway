package handlers

import (
	"net/http"
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/middleware"
	"secure-auth-gateway/internal/ratelimit"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

func RegisterSecureRoutes(r chi.Router, tokenMaker *auth.PasetoMaker, authHandler *AuthHandler) {
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.SecurityHeaders)
	r.Use(chiMiddleware.ClientIPFromXFF("172.16.0.0/12"))

	// Quick health check endpoint, public, no rate limits.
	r.Get("/api/v1/health", Health)

	// Public: rate-limited, no auth required.
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(httprate.Limit(10, 1*time.Minute,
			httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
				return httprate.CanonicalizeIP(chiMiddleware.GetClientIP(r.Context())), nil
			}),
			httprate.WithLimitCounter(ratelimit.LimitCounter),
		))
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// Protected: every route past here requires a valid token.
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthenticateToken(tokenMaker))

		// Admin-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("admin"))
		})

		// User-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("user"))
		})
	})
}

package handlers

import (
	"net/http"
	"secure-auth-gateway/internal/middleware"
	"secure-auth-gateway/internal/redis_db"
	"secure-auth-gateway/pkg/pasetoauth"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

func RegisterSecureRoutes(r chi.Router, authHandler *AuthHandler) {
	r.Use(chiMiddleware.Recoverer)
	r.Use(pasetoauth.SecurityHeaders)
	r.Use(chiMiddleware.ClientIPFromXFF("172.16.0.0/12"))

	// Quick health check endpoint, public, no rate limits.
	r.Get("/api/v1/health", Health)

	r.Get("/.well-known/paseto-public-key", PublicKeyHandler(authHandler.accessTokenMaker.PublicKey()))

	// Public: rate-limited, no auth required.
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(httprate.Limit(10, 1*time.Minute,
			httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
				return httprate.CanonicalizeIP(chiMiddleware.GetClientIP(r.Context())), nil
			}),
			httprate.WithLimitCounter(redis_db.LimitCounter),
		))
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.Refresh)
	})

	// Protected: every route past here requires a valid token.
	r.Group(func(r chi.Router) {
		r.Use(pasetoauth.AuthenticateToken(authHandler.accessTokenMaker.Verifier()))

		// Admin-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("admin"))
			r.Route("/api/v1/admin", func(r chi.Router) {
				r.Get("/health", adminHealth)
			})
		})

		// User-only.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("user"))
			r.Route("/api/v1/user/", func(r chi.Router) {
				r.Get("/health", userHealth)
			})
		})
	})
}

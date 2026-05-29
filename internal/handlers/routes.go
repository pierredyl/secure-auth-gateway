package handlers

import (
	"secure-auth-gateway/internal/auth"
	"secure-auth-gateway/internal/middleware"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

type CustomRouteBuilder func(
	adminRouter chi.Router,
	userRouter chi.Router,
	supportRouter chi.Router,
	billingRouter chi.Router,
)

func RegisterSecureRoutes(
	r chi.Router,
	tokenMaker *auth.PasetoMaker,
	db IdentityStore,
	buildRoutes CustomRouteBuilder,
) {
	// Middleware on the router
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(middleware.SecurityHeaders)

	authHandler := NewAuthHandler(tokenMaker, db)

	// 1. Public Route group
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(httprate.Limit(
			5,                                       // 5 requests
			1*time.Minute,                           // per minute
			httprate.WithKeyFuncs(httprate.KeyByIP), // By IP
		))

		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	adminGroup := r.With(
		middleware.AuthMiddleware(tokenMaker),
		middleware.RequireRole("admin"),
	)

	userGroup := r.With(
		middleware.AuthMiddleware(tokenMaker),
		middleware.RequireRole("user"),
	)

	supportGroup := r.With(
		middleware.AuthMiddleware(tokenMaker),
		middleware.RequireRole("support"),
	)

	billingGroup := r.With(
		middleware.AuthMiddleware(tokenMaker),
		middleware.RequireRole("billing"),
	)

	buildRoutes(adminGroup, userGroup, billingGroup, supportGroup)
}

package middleware

import "net/http"

// SecurityHeaders is the middleware that writes secure HTTP headers to any route.

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Prevent framing (clickjacking) attacks
		w.Header().Set("X-Frame-Options", "DENY")

		//Additionally deny from all ancestors using CSP
		w.Header().Set("Content-Security-Policy", "frame-ancestors `none`;")

		//Prevent MIME-Sniffing for XSS (cross site scripting)
		w.Header().Set("X-Content-Type-Options", "nosniff")

		//Force HTTPS using HSTS (HTTP Strict Transport Security) to prevent MITM (Man in the middle attack)
		w.Header().Set("Strict-Transport-Security", "max-age=6307200; includeSubDomains")

		//Enforce JSON responses
		w.Header().Set("Content-Type", "application/json")

		next.ServeHTTP(w, r)
	})
}

package pasetoauth

import "net/http"

// SecurityHeaders is middleware that sets response headers hardening a JSON API
// against clickjacking, MIME-sniffing and SSL-strip attacks. It sets
// X-Frame-Options, Content-Security-Policy (frame-ancestors),
// X-Content-Type-Options and Strict-Transport-Security, and touches nothing
// else — callers stay responsible for their own Content-Type.
//
// HSTS only means something behind a TLS-terminating proxy; over plaintext the
// header is advisory and browsers ignore it.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent framing (clickjacking) attacks
		w.Header().Set("X-Frame-Options", "DENY")

		// Additionally deny from all ancestors using CSP
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")

		// Prevent MIME-sniffing for XSS (cross site scripting)
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Force HTTPS using HSTS to prevent MITM (man in the middle) attacks.
		// Two years, the value HSTS preload submission requires.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

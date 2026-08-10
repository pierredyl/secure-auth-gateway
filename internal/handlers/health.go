package handlers

import "net/http"

// Health does no database work, no authentication, and no hashing. It exists as
// a capacity baseline: measuring it alongside /auth/login separates the cost of
// the stack's plumbing from the cost of Argon2id.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

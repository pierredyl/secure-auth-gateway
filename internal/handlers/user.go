package handlers

import "net/http"

func userHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"user endpoint successfully hit."}`))
}

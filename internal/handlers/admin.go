package handlers

import "net/http"

func adminHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"admin endpoint successfully hit."}`))
}

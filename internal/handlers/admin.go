package handlers

import (
	"encoding/json"
	"net/http"
)

type AdminHandler struct{}

func NewAdminHandler() *AdminHandler {
	return &AdminHandler{}
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome to the secure dashboard",
	})
}

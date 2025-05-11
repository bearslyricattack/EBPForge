package api

import (
	"awesomeProject2/internal/ebpf"
	"awesomeProject2/prometheus"
	"encoding/json"
	"fmt"
	"net/http"
)

type RegisterRequest struct {
	Name   string   `json:"name"`
	Help   string   `json:"help"`
	Type   string   `json:"type"` // "counter" 或 "gauge"
	Labels []string `json:"labels"`
	Path   string   `json:"path"`
}

func StartServer() {
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		err := ebpf.AddProgram(req.Name, req.Path, req.Type)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to register program: %v", err), http.StatusInternalServerError)
		}
		err = prometheus.RegisterMetric(req.Name, req.Help, req.Type, req.Labels)
		if err != nil {
			http.Error(w, fmt.Sprintf("Register error: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("registered"))
	})
	fmt.Println("API server started on :8080")
	http.ListenAndServe(":8080", nil)
}

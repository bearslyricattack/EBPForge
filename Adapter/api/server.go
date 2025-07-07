package api

import (
	"adapter/internal/ebpf"
	"adapter/prometheus"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type RegisterRequest struct {
	Name   string   `json:"name"`
	Help   string   `json:"help"`
	Type   string   `json:"type"` // "counter" or "gauge"
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

	// Query all registered eBPF programs
	http.HandleFunc("/programs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}

		programs := ebpf.ListPrograms()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(programs); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Query specific eBPF program
	http.HandleFunc("/program/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		// Extract program name from URL
		programName := strings.TrimPrefix(r.URL.Path, "/program/")
		if programName == "" {
			http.Error(w, "Program name is required", http.StatusBadRequest)
			return
		}
		program, _ := ebpf.GetProgram(programName)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(program); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Delete eBPF program
	http.HandleFunc("/unregister", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Only DELETE allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name string `json:"name"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "Program name is required", http.StatusBadRequest)
			return
		}
		// Remove eBPF program
		ebpf.RemoveProgram(req.Name)
		// Remove related Prometheus metrics
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("unregistered"))
	})

	fmt.Println("API Loader started on :8080")
	http.ListenAndServe(":8080", nil)
}

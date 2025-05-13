package api

import (
	"awesomeProject2/internal/ebpf"
	"awesomeProject2/prometheus"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

	// 查询所有已注册的eBPF程序
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

	// 查询特定eBPF程序
	http.HandleFunc("/program/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		// 从URL中提取程序名称
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

	// 删除eBPF程序
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
		// 移除eBPF程序
		ebpf.RemoveProgram(req.Name)
		// 移除相关的Prometheus指标
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("unregistered"))
	})

	fmt.Println("API server started on :8080")
	http.ListenAndServe(":8080", nil)
}

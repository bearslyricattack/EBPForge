package main

import (
	"awesomeProject2/bpftool"
	"awesomeProject2/prometheus"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Start Prometheus server in a goroutine
	go prometheus.StartPrometheusServer()

	// Create a ticker to periodically read BPF map data
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Channel to handle termination signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Monitoring process execution... Press Ctrl+C to stop.")
	// Goroutine to periodically fetch BPF data
	go func() {
		for {
			select {
			case <-ticker.C:
				output, err := bpftool.ReadMapUsingTool()
				if err != nil {
					fmt.Printf("Error reading BPF map: %v\n", err)
				} else {
					fmt.Println("BPF Map Data:", output)
				}
			}
		}
	}()

	// Wait for termination signal
	<-sig
	fmt.Println("\nShutting down gracefully...")
}

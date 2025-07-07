package main

import (
	"adapter/api"
	"adapter/prometheus"
	"adapter/timer"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var nodeFlag = flag.String("node", "unknown-node", "Node label to attach to all Prometheus metrics")
	flag.Parse()
	prometheus.Node = *nodeFlag
	flag.Parse()
	tickerInterval := 10 * time.Second
	timer.StartScheduler(tickerInterval)
	go prometheus.StartPrometheusServer("8080")
	go func() {
		fmt.Println("API Server starting on :8080...")
		api.StartServer()
	}()
	waitForShutdown()
}

func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Received signal: %s\n", s)
	fmt.Println("Shutting down gracefully...")
}

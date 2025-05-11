package main

import (
	"awesomeProject2/api"
	"awesomeProject2/prometheus"
	"awesomeProject2/timer"
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
	fmt.Println(prometheus.Node)
	flag.Parse()

	tickerInterval := 10 * time.Second
	timer.StartScheduler(tickerInterval)
	fmt.Println("Scheduler started.")

	// Start Prometheus server in a goroutine
	go prometheus.StartPrometheusServer()

	// 2. 启动 API Server（支持 /register 注册新指标）
	go func() {
		fmt.Println("API Server starting on :8080...")
		api.StartServer()
	}()

	// 3. 监听退出信号（Ctrl+C 或 kill）
	waitForShutdown()
}

func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Received signal: %s\n", s)
	fmt.Println("Shutting down gracefully...")
}

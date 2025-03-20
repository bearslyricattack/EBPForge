package prometheus

import (
	"awesomeProject2/pkg"
	"awesomeProject2/stdout"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(execveCounter)
	prometheus.MustRegister(execveInstancesGauge)
	prometheus.MustRegister(execveTotalCounter)
}

// Define Prometheus metrics
var (
	// Counter for total execve calls per process
	execveCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "execve_total_calls",
			Help: "Total number of execve calls by process name",
		},
		[]string{"process_name"},
	)

	// Gauge for tracking active process instances
	execveInstancesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "execve_instances",
			Help: "Number of process instances by process name",
		},
		[]string{"process_name"},
	)

	// Counter for total execve calls across all processes
	execveTotalCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "execve_all_calls_total",
			Help: "Total number of execve calls across all processes",
		},
	)
)

// StartPrometheusServer starts the Prometheus HTTP server
func StartPrometheusServer() {
	// Register the Prometheus metrics handler
	http.Handle("/metrics", promhttp.Handler())

	// Start the HTTP server
	fmt.Println("Starting Prometheus metrics server on :9093/metrics")
	if err := http.ListenAndServe(":9093", nil); err != nil {
		fmt.Printf("Failed to start Prometheus server: %v\n", err)
	}
}

// Track the last recorded total execve calls
var lastTotalCalls float64 = 0

// updatePrometheusMetrics updates Prometheus metrics with the latest process statistics
func updatePrometheusMetrics(stats []pkg.ProcessStat) {
	// Reset previous metric values
	execveCounter.Reset()
	execveInstancesGauge.Reset()

	// Update process-level metrics
	for _, stat := range stats {
		execveCounter.WithLabelValues(stat.Name).Add(float64(stat.TotalCount))
		execveInstancesGauge.WithLabelValues(stat.Name).Set(float64(stat.Executions))
	}

	// Compute total execve calls and update counter
	currentTotal := float64(stdout.SumTotalCounts(stats))
	if currentTotal > lastTotalCalls {
		execveTotalCounter.Add(currentTotal - lastTotalCalls)
	}

	// Store current total for next update comparison
	lastTotalCalls = currentTotal
}

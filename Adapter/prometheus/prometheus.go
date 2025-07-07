package prometheus

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sync"
)

var (
	dynamicGauges   = make(map[string]*prometheus.GaugeVec)
	dynamicCounters = make(map[string]*prometheus.CounterVec)
	lock            = sync.RWMutex{}
)

func RegisterGauge(name string, help string, labels []string) error {
	lock.Lock()
	defer lock.Unlock()
	if _, exists := dynamicGauges[name]; exists {
		return nil
	}
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels)
	if err := prometheus.Register(gauge); err != nil {
		return err
	}
	dynamicGauges[name] = gauge
	return nil
}

func RegisterCounter(name string, help string, labels []string) error {
	lock.Lock()
	defer lock.Unlock()
	if _, exists := dynamicCounters[name]; exists {
		return nil
	}
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labels)
	if err := prometheus.Register(counter); err != nil {
		fmt.Printf("Failed to register counter %s: %v\n", name, err)
		return err
	}
	dynamicCounters[name] = counter
	for counterName := range dynamicCounters {
		fmt.Printf("- %s\n", counterName)
	}
	return nil
}

// SetGauge sets the value of a GaugeVec
func SetGauge(name string, value uint64, labelValues ...string) {
	lock.RLock()
	defer lock.RUnlock()
	if gauge, exists := dynamicGauges[name]; exists {
		fmt.Printf("Found gauge %s, setting value\n", name)
		gauge.WithLabelValues(labelValues...).Set(float64(value))
		fmt.Printf("Successfully set gauge %s value to %d with label values %v\n", name, value, labelValues)
	} else {
		fmt.Printf("Warning: Gauge %s does not exist, cannot set value\n", name)
		// Optional: Print all available gauges
		if len(dynamicGauges) > 0 {
			fmt.Println("Currently available gauges:")
			for gaugeName := range dynamicGauges {
				fmt.Printf("- %s\n", gaugeName)
			}
		} else {
			fmt.Println("No gauges currently registered")
		}
	}
}

// AddCounter increments the value of a CounterVec
func AddCounter(name string, value uint64, labelValues ...string) {
	lock.RLock()
	defer lock.RUnlock()
	newLabelValues := append(labelValues, Node)
	if counter, exists := dynamicCounters[name]; exists {
		counter.WithLabelValues(newLabelValues...).Add(float64(value))
	} else {
		if len(dynamicCounters) > 0 {
			for counterName := range dynamicCounters {
				fmt.Printf("- %s\n", counterName)
			}
		} else {
			fmt.Println("No counters currently registered")
		}
	}
}

const (
	DefaultPrometheusPort = "9095"
)

// StartPrometheusServer starts the Prometheus HTTP server on the specified port
func StartPrometheusServer(port string) {
	http.Handle("/metrics", promhttp.Handler())
	// Use the provided port or default to 9095 if empty
	if port == "" {
		port = DefaultPrometheusPort
	}
	serverAddr := ":" + port
	fmt.Printf("Starting Prometheus metrics server on %s/metrics\n", serverAddr)

	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		fmt.Printf("Failed to start Prometheus server: %v\n", err)
	}
}

type MetricType string

const (
	GaugeType   MetricType = "Gauge"
	CounterType MetricType = "Counter"
)

var (
	Node string
)

func RegisterMetric(name string, help string, bpfType string, labels []string) error {
	labels = append(labels, Node)
	switch bpfType {
	case string(GaugeType):
		return RegisterGauge(name, help, labels)
	case string(CounterType):
		return RegisterCounter(name, help, labels)
	default:
		return fmt.Errorf("unsupported metric type: %s", bpfType)
	}
}

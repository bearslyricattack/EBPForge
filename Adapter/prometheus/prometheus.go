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

// RegisterGauge 注册一个新的 GaugeVec
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

// RegisterCounter 注册一个新的 CounterVec
func RegisterCounter(name string, help string, labels []string) error {
	lock.Lock()
	defer lock.Unlock()

	fmt.Printf("尝试注册计数器: %s\n", name)
	fmt.Printf("帮助信息: %s\n", help)
	fmt.Printf("标签列表: %v\n", labels)

	if _, exists := dynamicCounters[name]; exists {
		fmt.Printf("计数器 %s 已存在，跳过注册\n", name)
		return nil
	}

	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labels)

	fmt.Printf("创建了新的计数器: %s\n", name)

	if err := prometheus.Register(counter); err != nil {
		fmt.Printf("注册计数器 %s 失败: %v\n", name, err)
		return err
	}

	fmt.Printf("成功注册计数器 %s 到 Prometheus\n", name)
	dynamicCounters[name] = counter

	// 打印当前已注册的所有计数器
	fmt.Println("当前已注册的计数器列表:")
	for counterName := range dynamicCounters {
		fmt.Printf("- %s\n", counterName)
	}

	return nil
}

// SetGauge 设置 GaugeVec 的值
func SetGauge(name string, value uint64, labelValues ...string) {
	lock.RLock()
	defer lock.RUnlock()
	if gauge, exists := dynamicGauges[name]; exists {
		gauge.WithLabelValues(labelValues...).Set(float64(value))
	}
}

// AddCounter 累加 CounterVec 的值
func AddCounter(name string, value uint64, labelValues ...string) {
	lock.RLock()
	defer lock.RUnlock()
	if counter, exists := dynamicCounters[name]; exists {
		counter.WithLabelValues(labelValues...).Add(float64(value))
	}
}

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

type MetricType string

const (
	GaugeType   MetricType = "gauge"
	CounterType MetricType = "counter"
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

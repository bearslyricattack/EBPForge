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

	fmt.Printf("尝试设置仪表值: %s\n", name)
	fmt.Printf("设置值: %d\n", value)
	fmt.Printf("标签值: %v\n", labelValues)

	if gauge, exists := dynamicGauges[name]; exists {
		fmt.Printf("找到仪表 %s，正在设置值\n", name)
		gauge.WithLabelValues(labelValues...).Set(float64(value))
		fmt.Printf("成功设置仪表 %s 的值为 %d，标签值为 %v\n", name, value, labelValues)
	} else {
		fmt.Printf("警告: 仪表 %s 不存在，无法设置值\n", name)
		// 可选：打印当前所有可用的仪表
		if len(dynamicGauges) > 0 {
			fmt.Println("当前可用的仪表:")
			for gaugeName := range dynamicGauges {
				fmt.Printf("- %s\n", gaugeName)
			}
		} else {
			fmt.Println("当前没有注册的仪表")
		}
	}
}

// AddCounter 累加 CounterVec 的值
func AddCounter(name string, value uint64, labelValues ...string) {
	lock.RLock()
	defer lock.RUnlock()

	fmt.Printf("尝试累加计数器: %s\n", name)
	fmt.Printf("累加值: %d\n", value)
	fmt.Printf("标签值: %v\n", labelValues)

	if counter, exists := dynamicCounters[name]; exists {
		fmt.Printf("找到计数器 %s，正在累加值\n", name)
		counter.WithLabelValues(labelValues...).Add(float64(value))
		fmt.Printf("成功累加计数器 %s 的值 %d，标签值为 %v\n", name, value, labelValues)
	} else {
		fmt.Printf("警告: 计数器 %s 不存在，无法累加值\n", name)
		// 可选：打印当前所有可用的计数器
		if len(dynamicCounters) > 0 {
			fmt.Println("当前可用的计数器:")
			for counterName := range dynamicCounters {
				fmt.Printf("- %s\n", counterName)
			}
		} else {
			fmt.Println("当前没有注册的计数器")
		}
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

package timer

import (
	"adapter/internal/bpftool"
	"adapter/internal/decode"
	"adapter/internal/ebpf"
	"adapter/prometheus"
	"fmt"
	"time"
)

func StartScheduler(interval time.Duration) {
	fmt.Printf("start scheduler interval:%v\n", interval)
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			ReadAllEBPFPrograms()
		}
	}()
}

func ReadAllEBPFPrograms() {
	fmt.Printf("read all ebpf programs\n")
	for name, prog := range ebpf.ListPrograms() {
		fmt.Printf("Reading map for program: %s\n", name)
		fmt.Println(prog)
		output, err := bpftool.ReadMapUsingTool(prog.Path)
		if err != nil {
			fmt.Printf("Failed to read map for %s: %v\n", name, err)
			continue
		}
		parsed := decode.ParseBpftoolMapOutput(output)
		for label, value := range parsed {
			switch prog.Type {
			case "Counter":
				//fmt.Printf("Counter")
				prometheus.AddCounter(prog.Name, value, label)
			case "Gauge":
				//fmt.Printf("Gauge")
				prometheus.SetGauge(prog.Name, value, label)
			default:
				fmt.Printf("Unknown metric type '%s' for prog %s\n", prog.Type, prog.Name)
			}
		}
	}
}

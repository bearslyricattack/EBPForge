//package main
//
//import (
//	"flag"
//	"fmt"
//	"github.com/bearslyricattack/EBPForge/internal/compiler"
//	"github.com/bearslyricattack/EBPForge/internal/loader"
//	"github.com/bearslyricattack/EBPForge/internal/service"
//	pb "github.com/bearslyricattack/EBPForge/proto"
//	"google.golang.org/grpc"
//	"log"
//	"net"
//)
//
//var (
//	port = flag.Int("port", 50051, "The server port")
//)
//
//func main() {
//	flag.Parse()
//	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
//	if err != nil {
//		log.Fatalf("failed to listen: %v", err)
//	}
//
//	// Initialize compiler and loader
//	comp := compiler.NewCompiler()
//	load := loader.NewLoader()
//
//	// Create service with dependencies
//	svc := service.NewEbpfLoaderService(comp, load)
//
//	// Create gRPC server
//	s := grpc.NewServer()
//	pb.RegisterEbpfLoaderServer(s, svc)
//
//	log.Printf("server listening at %v", lis.Addr())
//	if err := s.Serve(lis); err != nil {
//		log.Fatalf("failed to serve: %v", err)
//	}
//}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	// 编译好的 eBPF 对象文件路径
	bpfObjectPath := "/home/sealos/wpy1/ebpf/EBPForge/eBPF/ebpf_map2.o"

	// 要挂载的内核函数名称
	kernelFunction := "sys_execve"

	fmt.Println("开始加载 kprobe 程序...")

	// 加载并附加 kprobe 程序，同时固定 maps
	kprobeLink, collection, err := loader.LoadKProbeProgram(bpfObjectPath, kernelFunction, true)
	if err != nil {
		log.Fatalf("加载 kprobe 程序失败: %v", err)
	}
	defer (*kprobeLink).Close()
	defer collection.Close()

	// maps 已固定，可以通过 BPF 文件系统访问
	fmt.Println("Maps 已固定到 /sys/fs/bpf/sys_execve/ 目录")
	// 创建一个 ticker 定时读取 map 数据
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 等待中断信号以终止程序
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("开始监控进程执行信息...")

	go func() {
		for {
			select {
			case <-ticker.C:
				// 使用 bpftool 读取 map
				readMapUsingBpftool()
			}
		}
	}()

	<-sig
	fmt.Println("\n程序终止")
}

// 使用 bpftool 读取 map
func readMapUsingBpftool() {
	fmt.Println("\n当前进程执行信息:")

	// 执行 bpftool 命令读取 map
	cmd := exec.Command("bpftool", "map", "dump", "pinned", "/sys/fs/bpf/sys_execve/proc_execve")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("执行 bpftool 失败: %v\n", err)
		return
	}

	// 解析输出并格式化显示
	processMapOutput(string(output))
}

// 解析并格式化 bpftool 的输出，按进程名称统计调用次数
func processMapOutput(output string) {
	// 清理输出，删除杂项字符
	cleanOutput := strings.ReplaceAll(output, "------------------------------------------", "")

	// 尝试将输出作为JSON解析
	var entries []struct {
		Key   int `json:"key"`
		Value struct {
			Comm  string `json:"comm"`
			Pid   int    `json:"pid"`
			Count int    `json:"count"`
		} `json:"value"`
	}

	err := json.Unmarshal([]byte(cleanOutput), &entries)
	if err != nil {
		fmt.Printf("JSON解析错误: %v\n", err)
		return
	}

	// 按进程名称统计调用次数
	processStats := make(map[string]struct {
		TotalCount int
		Executions int
		ProcessIDs []int
	})

	for _, entry := range entries {
		procName := entry.Value.Comm
		stats := processStats[procName]
		stats.TotalCount += entry.Value.Count
		stats.Executions++
		stats.ProcessIDs = append(stats.ProcessIDs, entry.Value.Pid)
		processStats[procName] = stats
	}

	var statsList []ProcessStat

	for name, stats := range processStats {
		statsList = append(statsList, ProcessStat{
			Name:       name,
			TotalCount: stats.TotalCount,
			Executions: stats.Executions,
			ProcessIDs: stats.ProcessIDs,
		})
	}

	// 按总调用次数降序排序
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].TotalCount > statsList[j].TotalCount
	})

	// 显示统计结果
	fmt.Printf("\n%-20s %-15s %-15s %-20s\n", "进程名", "总调用次数", "执行进程数", "PID列表(部分)")
	fmt.Println(strings.Repeat("-", 75))

	for _, stat := range statsList {
		// 只显示前5个PID，如果超过5个则显示"等"
		pidDisplay := ""
		if len(stat.ProcessIDs) <= 5 {
			for i, pid := range stat.ProcessIDs {
				if i > 0 {
					pidDisplay += ", "
				}
				pidDisplay += fmt.Sprintf("%d", pid)
			}
		} else {
			for i := 0; i < 5; i++ {
				if i > 0 {
					pidDisplay += ", "
				}
				pidDisplay += fmt.Sprintf("%d", stat.ProcessIDs[i])
			}
			pidDisplay += fmt.Sprintf(" 等%d个", len(stat.ProcessIDs))
		}

		fmt.Printf("%-20s %-15d %-15d %-20s\n",
			stat.Name, stat.TotalCount, stat.Executions, pidDisplay)
	}

	// 显示统计总数
	fmt.Printf("\n共发现 %d 个不同进程，总调用次数: %d\n",
		len(statsList), sumTotalCounts(statsList))
}

// 转换为切片以便排序
type ProcessStat struct {
	Name       string
	TotalCount int
	Executions int
	ProcessIDs []int
}

// 计算总调用次数
func sumTotalCounts(stats []ProcessStat) int {
	total := 0
	for _, stat := range stats {
		total += stat.TotalCount
	}
	return total
}

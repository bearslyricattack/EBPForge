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
	"fmt"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
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

	fmt.Println(output)
	if err != nil {
		fmt.Printf("执行 bpftool 失败: %v\n", err)
		fmt.Println(string(output))
		return
	}

	// 解析输出并格式化显示
	processMapOutput(string(output))
}

// 解析并格式化 bpftool 的输出
func processMapOutput(output string) {
	fmt.Printf("%-20s %-10s %-10s\n", "进程名", "PID", "执行次数")
	fmt.Println(strings.Repeat("-", 42))

	// 按行分割输出
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fmt.Println(line)
	}

	// 用于存储解析后的数据
	type ProcessData struct {
		Pid   uint32
		Comm  string
		Count uint64
	}

	var processes []ProcessData

	// 解析每一行
	for _, line := range lines {
		// 查找包含 key 和 value 的行
		if strings.Contains(line, "key:") && strings.Contains(line, "value:") {
			// 解析 key (pid)
			keyMatch := regexp.MustCompile(`key:\s+(\d+)`).FindStringSubmatch(line)
			if len(keyMatch) < 2 {
				continue
			}

			pid, err := strconv.ParseUint(keyMatch[1], 10, 32)
			if err != nil {
				continue
			}

			// 解析 comm (进程名)
			// 假设格式为: value: { comm: <进程名>, ... }
			commMatch := regexp.MustCompile(`comm:\s+(\S+)`).FindStringSubmatch(line)
			if len(commMatch) < 2 {
				continue
			}
			comm := commMatch[1]

			// 解析 count (执行次数)
			countMatch := regexp.MustCompile(`count:\s+(\d+)`).FindStringSubmatch(line)
			if len(countMatch) < 2 {
				continue
			}

			count, err := strconv.ParseUint(countMatch[1], 10, 64)
			if err != nil {
				continue
			}

			// 添加到进程列表
			processes = append(processes, ProcessData{
				Pid:   uint32(pid),
				Comm:  comm,
				Count: count,
			})
		}
	}

	// 按执行次数排序（从高到低）
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Count > processes[j].Count
	})

	// 显示排序后的进程信息
	for _, proc := range processes {
		fmt.Printf("%-20s %-10d %-10d\n", proc.Comm, proc.Pid, proc.Count)
	}

	// 如果没有进程信息
	if len(processes) == 0 {
		fmt.Println("暂无进程执行信息")
	}
}

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

// 解析并格式化 bpftool 的输出
func processMapOutput(output string) {
	fmt.Printf("%-20s %-10s %-10s\n", "进程名", "PID", "执行次数")
	fmt.Println(strings.Repeat("-", 42))

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

	// 显示结果
	for _, entry := range entries {
		fmt.Printf("%-20s %-10d %-10d\n", entry.Value.Comm, entry.Value.Pid, entry.Value.Count)
	}

	// 显示数据总数
	fmt.Printf("\n共发现 %d 条进程记录\n", len(entries))
}

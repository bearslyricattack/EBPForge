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
	"github.com/cilium/ebpf"
	"log"
	"os"
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

	// 获取 eBPF map
	procExecveMap, found := collection.Maps["proc_execve"]
	if !found {
		log.Fatalf("找不到 proc_execve map")
	}

	// 创建一个 ticker 定时读取 map 数据
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// 等待中断信号以终止程序
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("开始监控进程执行信息...")

	go func() {
		for {
			select {
			case <-ticker.C:
				// 读取并显示 map 内容
				readProcExecveMap(procExecveMap)
			}
		}
	}()

	<-sig
	fmt.Println("\n程序终止")
}

// ProcInfo 定义与 eBPF 中相匹配的 Go 结构体
type ProcInfo struct {
	Comm  [16]byte // 进程名 (TASK_COMM_LEN)
	Pid   uint32   // 进程ID
	Count uint64   // 执行次数计数
}

// 读取并显示进程执行信息
func readProcExecveMap(m *ebpf.Map) {
	fmt.Println("\n当前进程执行信息:")
	fmt.Printf("%-20s %-10s %-10s\n", "进程名", "PID", "执行次数")
	fmt.Println(strings.Repeat("-", 42))

	// 创建迭代器
	iter := m.Iterate()

	// 定义键值变量
	var key uint32
	var value ProcInfo

	// 迭代所有条目
	for iter.Next(&key, &value) {
		// 将进程名从 [16]byte 转换为字符串并去除空字符
		commStr := strings.TrimRight(string(value.Comm[:]), "\x00")

		// 显示数据
		fmt.Printf("%-20s %-10d %-10d\n", commStr, value.Pid, value.Count)
	}

	// 检查迭代过程中是否有错误
	if err := iter.Err(); err != nil {
		fmt.Printf("迭代错误: %v\n", err)
	}
}

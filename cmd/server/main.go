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
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 编译好的 eBPF 对象文件路径
	bpfObjectPath := "/path/to/your/compiled/bpf/program.o"

	// 要挂载的内核函数名称
	kernelFunction := "sys_execve"

	fmt.Println("开始加载 kprobe 程序...")

	// 加载并附加 kprobe 程序
	kprobeLink, err := loader.LoadKProbeProgram(bpfObjectPath, kernelFunction)
	if err != nil {
		log.Fatalf("加载 kprobe 程序失败: %v", err)
	}
	defer (*kprobeLink).Close()

	log.Printf("kprobe 程序已成功加载并附加到内核函数 %s\n", kernelFunction)

	// 获取 eBPF maps 以便读取数据
	collection, err := loader.GetMapsReader(bpfObjectPath)
	if err != nil {
		log.Fatalf("获取 maps reader 失败: %v", err)
	}
	defer collection.Close()

	// 获取 "syscall_counts" map
	countsMap, ok := collection.Maps["syscall_counts"]
	if !ok {
		log.Fatalf("未找到名为 'syscall_counts' 的 map")
	}

	// 开始定期打印 map 内容
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for range ticker.C {
			// 读取 map 中的所有条目
			var key uint32
			var value uint64

			entries := make(map[uint32]uint64)
			iter := countsMap.Iterate()
			for iter.Next(&key, &value) {
				entries[key] = value
			}

			if len(entries) > 0 {
				fmt.Println("\n进程 execve 调用次数:")
				fmt.Println("PID\t调用次数")
				fmt.Println("---\t--------")

				for pid, count := range entries {
					fmt.Printf("%d\t%d\n", pid, count)
				}
			}
		}
	}()

	// 等待中断信号以终止程序
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ticker.Stop()
	fmt.Println("\n程序终止")
}

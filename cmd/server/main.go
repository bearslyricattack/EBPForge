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

	// 等待中断信号以终止程序
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n程序终止")
}

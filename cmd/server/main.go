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
	"github.com/bearslyricattack/EBPForge/eBPF"
	"github.com/bearslyricattack/EBPForge/internal/compiler"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 创建编译器实例，使用系统临时目录
	compiler := &compiler.Compiler{
		TempDir: os.TempDir(),
	}
	fmt.Println("开始编译BPF程序...")
	// 编译BPF程序
	objFile, err := compiler.Compile(eBPF.SampleBPFProgram)
	if err != nil {
		fmt.Printf("编译失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("编译成功！\nBPF对象文件路径: %s\n", objFile)
	fmt.Println("开始加载BPF程序...")
	bpfObjectPath := objFile
	interfaceName := "ens18"
	xdpLink, err := loader.LoadXDPProgram(bpfObjectPath, interfaceName)
	if err != nil {
		log.Fatalf("加载XDP程序失败: %v", err)
	}
	defer (*xdpLink).Close()
	log.Printf("XDP程序已成功加载到接口 %s\n", interfaceName)
	// 程序将保持运行状态，直到接收到终止信号
	fmt.Println("按Ctrl+C终止程序...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

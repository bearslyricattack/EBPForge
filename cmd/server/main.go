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
	"github.com/bearslyricattack/EBPForge/internal/compiler"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 编译 eBPF 程序
	c := compiler.NewCompiler()
	res, err := c.Compile("/home/sealos/wpy1/ebpf/EBPForge/eBPF", "ebpf_map2")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("编译结果:", res)

	// 编译好的 eBPF 对象文件路径
	bpfObjectPath := res
	// 要挂载的内核函数名称
	kernelFunction := "sys_execve"
	fmt.Println("开始加载 kprobe 程序...")

	// 加载并附加 kprobe 程序，同时固定 maps
	kprobeLink, collection, err := loader.LoadKProbeProgram(bpfObjectPath, kernelFunction, true)
	if err != nil {
		log.Fatalf("加载 kprobe 程序失败: %v", err)
	}

	// 注意：根据需要可以取消下面的 defer 语句注释
	// defer (*kprobeLink).Close()
	// defer collection.Close()

	// maps 已固定，可以通过 BPF 文件系统访问
	fmt.Println("Maps 已固定到 /sys/fs/bpf/sys_execve/ 目录")

	// 创建一个通道接收信号
	sigChan := make(chan os.Signal, 1)
	// 注册要监听的信号
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("程序正在运行中，按 Ctrl+C 停止...")

	// 可以添加一个简单的状态输出循环
	go func() {
		for {
			fmt.Println("eBPF 程序正在运行...", time.Now().Format("2006-01-02 15:04:05"))
			time.Sleep(30 * time.Second)
		}
	}()

	// 阻塞直到接收到信号
	sig := <-sigChan
	fmt.Printf("接收到信号: %v，正在关闭程序...\n", sig)

	// 如果想在程序退出前手动清理资源，可以在这里添加清理代码
	fmt.Println("正在清理资源...")

	// 如果前面没有使用 defer，可以在这里显式关闭资源
	if kprobeLink != nil {
		(*kprobeLink).Close()
		fmt.Println("已关闭 kprobe 链接")
	}

	if collection != nil {
		collection.Close()
		fmt.Println("已关闭 BPF 集合")
	}

	fmt.Println("程序已安全退出")
}

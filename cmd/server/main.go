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
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// LoadXDPProgram 加载eBPF程序到指定网络接口的XDP挂载点
func LoadXDPProgram(bpfObjectPath, interfaceName string) (*link.Link, error) {
	// 打开编译好的eBPF对象文件
	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, fmt.Errorf("加载eBPF对象文件失败: %w", err)
	}

	// 加载eBPF集合
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("创建eBPF集合失败: %w", err)
	}
	defer coll.Close()

	// 获取XDP程序
	xdpProg, ok := coll.Programs["xdp_prog"]
	if !ok {
		return nil, fmt.Errorf("eBPF对象中未找到名为'xdp_prog'的程序")
	}

	// 获取网络接口的索引
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("获取网络接口'%s'失败: %w", interfaceName, err)
	}

	// 将XDP程序附加到网络接口
	// 使用默认标志(XDPGenericMode)，可以根据需要修改为XDPDriverMode或XDPOffloadMode
	opts := link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	}

	xdpLink, err := link.AttachXDP(opts)
	if err != nil {
		return nil, fmt.Errorf("将XDP程序附加到接口'%s'失败: %w", interfaceName, err)
	}

	return &xdpLink, nil
}

func main() {
	// 示例用法
	if len(os.Args) < 3 {
		log.Fatalf("用法: %s <eBPF程序路径> <网络接口名称>", os.Args[0])
	}

	bpfObjectPath := os.Args[1]
	interfaceName := os.Args[2]

	xdpLink, err := LoadXDPProgram(bpfObjectPath, interfaceName)
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

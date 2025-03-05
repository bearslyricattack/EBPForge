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
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gin-gonic/gin"
	"log"
)

var cp compiler.Compiler

var (
	kprobeLink *link.Link
	collection *ebpf.Collection
)

// 加载eBPF程序的处理函数
func loadHandler(c *gin.Context) {
	path := c.Query("path")
	filename := c.Query("name")

	// 打印参数值进行调试
	fmt.Printf("收到参数 - path: %s, filename: %s\n", path, filename)

	res, err := cp.Compile(path, filename)
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
	kprobeLink, collection, err = loader.LoadKProbeProgram(bpfObjectPath, kernelFunction, true)
	if err != nil {
		log.Fatalf("加载 kprobe 程序失败: %v", err)
	}
	// maps 已固定，可以通过 BPF 文件系统访问
	fmt.Println("Maps 已固定到 /sys/fs/bpf/sys_execve/ 目录")
}
func main() {
	// 创建Gin默认路由
	r := gin.Default()

	// 设置路由
	r.GET("/load", loadHandler)
	fmt.Println("HTTP服务器正在启动，监听端口 :8082")
	r.Run(":8082")

	// 注意：根据需要可以取消下面的 defer 语句注释
	defer (*kprobeLink).Close()
	defer collection.Close()
}

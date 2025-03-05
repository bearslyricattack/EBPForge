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
	"github.com/gin-gonic/gin"
	"log"
	"time"
)

var cp compiler.Compiler

// 加载eBPF程序的处理函数
func loadHandler(c *gin.Context) {
	path := c.Query("path")
	filename := c.Query("filename")

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
	kprobeLink, collection, err := loader.LoadKProbeProgram(bpfObjectPath, kernelFunction, true)
	if err != nil {
		log.Fatalf("加载 kprobe 程序失败: %v", err)
	}
	// 注意：根据需要可以取消下面的 defer 语句注释
	defer (*kprobeLink).Close()
	defer collection.Close()
	// maps 已固定，可以通过 BPF 文件系统访问
	fmt.Println("Maps 已固定到 /sys/fs/bpf/sys_execve/ 目录")

}
func main() {
	// 创建Gin默认路由
	r := gin.Default()

	// 设置路由
	r.GET("/load", loadHandler)
	// 启动HTTP服务器，修改端口为9090
	go func() {
		fmt.Println("HTTP服务器正在启动，监听端口 :8082")
		if err := r.Run(":8082"); err != nil {
			log.Fatalf("HTTP服务器错误: %v", err)
		}
	}()

	// 可以添加一个简单的状态输出循环
	go func() {
		for {
			fmt.Println("HTTP服务器正在运行...", time.Now().Format("2006-01-02 15:04:05"))
			time.Sleep(30 * time.Second)
		}
	}()

	fmt.Println("程序正在运行中，按 Ctrl+C 停止...")
}

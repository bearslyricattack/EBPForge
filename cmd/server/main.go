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
	"os"
	"path/filepath"
)

//func main() {
//	// 示例用法
//	if len(os.Args) < 3 {
//		log.Fatalf("用法: %s <eBPF程序路径> <网络接口名称>", os.Args[0])
//	}
//
//	bpfObjectPath := os.Args[1]
//	interfaceName := os.Args[2]
//
//	xdpLink, err := loader.LoadXDPProgram(bpfObjectPath, interfaceName)
//	if err != nil {
//		log.Fatalf("加载XDP程序失败: %v", err)
//	}
//	defer (*xdpLink).Close()
//
//	log.Printf("XDP程序已成功加载到接口 %s\n", interfaceName)
//
//	// 程序将保持运行状态，直到接收到终止信号
//	fmt.Println("按Ctrl+C终止程序...")
//	sig := make(chan os.Signal, 1)
//	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
//	<-sig
//}

// 简单的BPF程序示例
const sampleBPFProgram = `
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

// 这是一个简单的BPF程序，它会计数所有经过的IP包
int count_ip_packets(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 检查数据是否足够包含以太网头部
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    
    // 检查是否是IP包
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        // 这里只是简单返回，实际应用中可能会更新某个映射(map)来计数
        return TC_ACT_OK;
    }
    
    return TC_ACT_OK;
}
`

func main() {
	// 创建编译器实例，使用系统临时目录
	compiler := &compiler.Compiler{
		TempDir: os.TempDir(),
	}
	fmt.Println("开始编译BPF程序...")
	// 编译BPF程序
	objFile, err := compiler.Compile(sampleBPFProgram)
	if err != nil {
		fmt.Printf("编译失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("编译成功！\nBPF对象文件路径: %s\n", objFile)
	// 检查对象文件是否存在并获取文件大小
	fileInfo, err := os.Stat(objFile)
	if err != nil {
		fmt.Printf("无法获取对象文件信息: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("对象文件大小: %d 字节\n", fileInfo.Size())
	fmt.Printf("如果您不再需要生成的文件，请手动删除目录: %s\n", filepath.Dir(objFile))
}

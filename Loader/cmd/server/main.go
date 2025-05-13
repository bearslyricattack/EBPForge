package main

import (
	"fmt"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"github.com/bearslyricattack/EBPForge/pkg"
	"log"

	"github.com/bearslyricattack/EBPForge/internal/compiler"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gin-gonic/gin"
)

const (
	AttachKprobe     AttachType = "kprobe"
	AttachKretprobe  AttachType = "kretprobe"
	AttachTracepoint AttachType = "tracepoint"
	AttachUprobe     AttachType = "uprobe"
	AttachUretprobe  AttachType = "uretprobe"
	AttachXDP        AttachType = "xdp"
	AttachTC         AttachType = "tc"
	AttachSockFilter AttachType = "sockfilter"
	AttachCgroupSock AttachType = "cgroup_sock"
	AttachLSM        AttachType = "lsm"
)

// AttachType 挂载类型定义
type AttachType string

var (
	kprobeLink link.Link
	collection *ebpf.Collection
)

func loadHandler(c *gin.Context) {
	name := c.Query("name")
	target := c.Query("target")
	ebpftype := c.Query("type")
	code := c.Query("code")
	program := c.Query("program")
	fmt.Println("name:", name, "target:", target, "type:", ebpftype, "code:", code, "program:", program)
	// 编译
	path, err := compiler.CompileFromCode(code, name)
	fmt.Println("编译成功！当前的文件位置是path:", path)
	if err != nil {
		c.JSON(500, gin.H{
			"error": fmt.Sprintf("编译失败: %v", err),
		})
		return
	}
	//挂载
	var args pkg.AttachArgs
	args.Name = name
	args.Target = target
	args.Ebpftype = ebpftype
	args.Code = code
	args.Program = program
	_, collection, err = loader.LoadAndAttachBPF(path, args)
	if err != nil {
		c.JSON(500, gin.H{
			"error": fmt.Sprintf("加载 kprobe 程序失败: %v", err),
		})
		return
	}
	c.JSON(200, gin.H{
		"status":  "success",
		"message": fmt.Sprintf("程序已加载并挂载到 %s", path),
	})
}

// 查询所有加载的eBPF程序状态
func loadStatusHandler(c *gin.Context) {
	//调用bpf tool 返回
	// 返回所有加载的程序
	//c.JSON(200, )
}

// 卸载eBPF程序
func unloadHandler(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(400, gin.H{
			"error": "必须提供程序名称",
		})
		return
	}
	//调用bpf tool 返回
	c.JSON(200, gin.H{
		"status":  "success",
		"message": fmt.Sprintf("程序 %s 已成功卸载", name),
	})
}

func main() {
	r := gin.Default()
	r.GET("/load", loadHandler)
	fmt.Println("HTTP服务器正在启动，监听端口 :8082")
	defer func() {
		if kprobeLink != nil {
			kprobeLink.Close()
		}
		if collection != nil {
			collection.Close()
		}
	}()
	if err := r.Run(":8082"); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}

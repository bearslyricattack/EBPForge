package main

import (
	"fmt"
	"log"

	"github.com/bearslyricattack/EBPForge/internal/compiler"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gin-gonic/gin"
)

var (
	kprobeLink link.Link
	collection *ebpf.Collection
)

func loadHandler(c *gin.Context) {
	name := c.Query("name")
	target := c.Query("target")
	ebpftype := c.Query("type")
	code := c.Query("code")
	fmt.Println("name:", name, "target:", target, "type:", ebpftype, "code:", code)
	// 编译
	path, err := compiler.CompileFromCode(code, name)
	if err != nil {
		c.JSON(500, gin.H{
			"error": fmt.Sprintf("编译失败: %v", err),
		})
		return
	}
	//挂载
	//var lnk link.Link
	//lnk, collection, err = loader.LoadAndAttachBPF(bpfObjectPath, attachArgs)
	//if err != nil {
	//	c.JSON(500, gin.H{
	//		"error": fmt.Sprintf("加载 kprobe 程序失败: %v", err),
	//	})
	//	return
	//}
	c.JSON(200, gin.H{
		"status":  "success",
		"message": fmt.Sprintf("程序已加载并挂载到 %s", path),
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

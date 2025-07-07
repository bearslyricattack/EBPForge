package main

import (
	"fmt"
	"github.com/bearslyricattack/EBPForge/internal/loader"
	"github.com/bearslyricattack/EBPForge/pkg"
	"log"
	"os"

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

// AttachType defines the type of eBPF program attachment
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
	// Compile
	path, err := compiler.CompileFromCode(code, name)
	fmt.Println("Compilation successful! Current file location is path:", path)
	if err != nil {
		c.JSON(500, gin.H{
			"error": fmt.Sprintf("Compilation failed: %v", err),
		})
		return
	}
	// Attach
	var args pkg.AttachArgs
	args.Name = name
	args.Target = target
	args.Ebpftype = ebpftype
	args.Code = code
	args.Program = program
	_, collection, err = loader.LoadAndAttachBPF(path, args)
	if err != nil {
		c.JSON(500, gin.H{
			"error": fmt.Sprintf("Failed to load eBPF program, program type %s: %v", ebpftype, err),
		})
		return
	}
	c.JSON(200, gin.H{
		"status":  "success",
		"message": fmt.Sprintf("Program loaded and attached to %s", path),
	})
}

// Query the status of all loaded eBPF programs
func loadStatusHandler(c *gin.Context) {
	// Call bpf tool and return
	// Return all loaded programs
	//c.JSON(200, )
}

// Unload eBPF program
func unloadHandler(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(400, gin.H{
			"error": "Program name must be provided",
		})
		return
	}
	// Call bpf tool and return
	c.JSON(200, gin.H{
		"status":  "success",
		"message": fmt.Sprintf("Program %s has been successfully unloaded", name),
	})
}

func main() {
	port := ":8082"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = ":" + envPort
	}
	r := gin.Default()
	r.GET("/load", loadHandler)
	fmt.Printf("HTTP server starting, listening on port %s\n", port)
	defer func() {
		if kprobeLink != nil {
			kprobeLink.Close()
		}
		if collection != nil {
			collection.Close()
		}
	}()
	if err := r.Run(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

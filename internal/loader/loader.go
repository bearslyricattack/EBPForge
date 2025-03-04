package loader

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
	"os"
	"path/filepath"
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

// LoadKProbeProgram 加载eBPF程序到kprobe挂载点并固定maps
func LoadKProbeProgram(bpfObjectPath, fnName string, pinMaps bool) (*link.Link, *ebpf.Collection, error) {
	// 打开编译好的eBPF对象文件
	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("加载eBPF对象文件失败: %w", err)
	}

	// 加载eBPF集合
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("创建eBPF集合失败: %w", err)
	}

	// 查找可能的程序名格式
	programName := fmt.Sprintf("kprobe__%s", fnName) // 尝试常见的命名约定
	kprobeProgram, ok := coll.Programs[programName]

	// 如果找不到，尝试直接使用函数名
	if !ok {
		kprobeProgram, ok = coll.Programs[fnName]
		if !ok {
			// 列出所有可用的程序名
			availableProgs := make([]string, 0, len(coll.Programs))
			for name := range coll.Programs {
				availableProgs = append(availableProgs, name)
			}
			coll.Close()
			return nil, nil, fmt.Errorf("eBPF对象中未找到名为'%s'或'kprobe__%s'的程序，可用程序: %v",
				fnName, fnName, availableProgs)
		}
	}

	// 将kprobe程序附加到指定的内核函数
	kprobeLink, err := link.Kprobe(fnName, kprobeProgram, nil)
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("将kprobe程序附加到函数'%s'失败: %w", fnName, err)
	}

	// 如果需要，将maps固定到BPF文件系统
	if pinMaps {
		bpfFSPath := "/sys/fs/bpf"

		// 确保BPF文件系统目录存在
		if err := os.MkdirAll(bpfFSPath, 0755); err != nil {
			kprobeLink.Close()
			coll.Close()
			return nil, nil, fmt.Errorf("创建BPF文件系统目录失败: %w", err)
		}

		// 为程序创建子目录
		progDir := filepath.Join(bpfFSPath, fnName)
		if err := os.MkdirAll(progDir, 0755); err != nil {
			kprobeLink.Close()
			coll.Close()
			return nil, nil, fmt.Errorf("创建程序目录失败: %w", err)
		}

		// 固定所有maps
		for mapName, m := range coll.Maps {
			mapPath := filepath.Join(progDir, mapName)

			// 如果已存在，先删除
			if _, err := os.Stat(mapPath); err == nil {
				if err := os.Remove(mapPath); err != nil {
					kprobeLink.Close()
					coll.Close()
					return nil, nil, fmt.Errorf("删除现有固定map失败: %w", err)
				}
			}

			// 固定map
			if err := m.Pin(mapPath); err != nil {
				kprobeLink.Close()
				coll.Close()
				return nil, nil, fmt.Errorf("固定map '%s'失败: %w", mapName, err)
			}

			fmt.Printf("Map '%s' 已固定到: %s\n", mapName, mapPath)
		}
	}

	// 返回链接和集合，这样调用者可以访问maps
	return &kprobeLink, coll, nil
}

// GetMapsReader 创建一个用于读取eBPF maps的reader
func GetMapsReader(bpfObjectPath string) (*ebpf.Collection, error) {
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

	return coll, nil
}

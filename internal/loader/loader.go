package loader

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
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

// LoadKProbeProgram 加载eBPF程序到kprobe挂载点
func LoadKProbeProgram(bpfObjectPath, fnName string) (*link.Link, error) {
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
			return nil, fmt.Errorf("eBPF对象中未找到名为'%s'或'kprobe__%s'的程序，可用程序: %v",
				fnName, fnName, availableProgs)
		}
	}

	// 将kprobe程序附加到指定的内核函数
	kprobeLink, err := link.Kprobe(fnName, kprobeProgram, nil)
	if err != nil {
		return nil, fmt.Errorf("将kprobe程序附加到函数'%s'失败: %w", fnName, err)
	}

	return &kprobeLink, nil
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

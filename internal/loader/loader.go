package loader

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
)

// LoadXDPProgram 加载eBPF程序到指定网络接口的XDP挂载点
func LoadXDPProgram(bpfObjectPath, interfaceName string) (*link.Link, error) {
	fmt.Println(bpfObjectPath)
	fmt.Println(interfaceName)
	// 打开编译好的eBPF对象文件
	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, fmt.Errorf("加载eBPF对象文件失败: %w", err)
	}
	// 输出解析的eBPF对象文件内容
	fmt.Printf("成功加载eBPF对象文件: %s\n", bpfObjectPath)
	fmt.Println("==== eBPF对象文件内容 ====")

	// 输出所有程序
	if len(spec.Programs) > 0 {
		fmt.Println("\n程序列表:")
		for name, prog := range spec.Programs {
			fmt.Printf("  - 程序名: %s\n", name)
			fmt.Printf("    类型: %s\n", prog.Type)
			fmt.Printf("    许可证: %s\n", prog.License)
			fmt.Printf("    指令数量: %d\n", len(prog.Instructions))

			// 输出更详细的指令信息（可选择前10条指令）
			if len(prog.Instructions) > 0 {
				fmt.Println("    前10条指令预览:")
				maxInstr := 10
				if len(prog.Instructions) < maxInstr {
					maxInstr = len(prog.Instructions)
				}
				for i := 0; i < maxInstr; i++ {
					fmt.Printf("      %d: %v\n", i, prog.Instructions[i])
				}
			}
			fmt.Println()
		}
	} else {
		fmt.Println("没有找到程序")
	}

	// 加载eBPF集合
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("创建eBPF集合失败: %w", err)
	}
	defer coll.Close()

	fmt.Println(coll)
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

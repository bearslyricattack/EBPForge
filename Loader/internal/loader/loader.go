package loader

import (
	"errors"
	"fmt"
	"github.com/bearslyricattack/EBPForge/pkg"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"net"
	"strings"
)

// AttachType 挂载类型定义
type AttachType string

const (
	AttachKprobe     string = "kprobe"
	AttachKretprobe  string = "kretprobe"
	AttachTracepoint string = "tracepoint"
	AttachUprobe     string = "uprobe"
	AttachUretprobe  string = "uretprobe"
	AttachXDP        string = "xdp"
	AttachTC         string = "tc"
	AttachSockFilter string = "sockfilter"
	AttachCgroupSock string = "cgroup_sock"
	AttachLSM        string = "lsm"
)

func LoadAndAttachBPF(bpfObjectPath string, args pkg.AttachArgs) (link.Link, *ebpf.Collection, error) {
	// 0. 解除 MEMLOCK 限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("解除MEMLOCK限制失败: %w", err)
	}
	// 1. 加载 eBPF 对象文件
	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("加载eBPF对象文件失败: %w", err)
	}

	// 2. 加载 collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("创建eBPF集合失败: %w", err)
	}

	// 3. 查找程序
	prog, ok := coll.Programs[args.Program]
	if !ok {
		// 输出可用程序名
		availableProgs := make([]string, 0, len(coll.Programs))
		for name := range coll.Programs {
			availableProgs = append(availableProgs, name)
		}
		coll.Close()
		return nil, nil, fmt.Errorf("未找到程序 '%s'，可用: %v", args.Name, availableProgs)
	}

	var lnk link.Link

	switch args.Ebpftype {
	case AttachKprobe:
		fmt.Println(1211111)
		lnk, err = link.Kprobe(args.Target, prog, nil)
	case AttachKretprobe:
		lnk, err = link.Kretprobe(args.Target, prog, nil)
	case AttachTracepoint:
		// Target 格式: "subsys:event"
		ss, ev, ok := strings.Cut(args.Target, ":")
		if !ok {
			coll.Close()
			return nil, nil, errors.New("tracepoint Target 格式应为 'subsys:event'")
		}
		lnk, err = link.Tracepoint(ss, ev, prog, nil)
	case AttachXDP:
		iface, err2 := netInterfaceByName(args.Target)
		if err2 != nil {
			coll.Close()
			return nil, nil, fmt.Errorf("获取网卡失败: %w", err2)
		}
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
	case AttachSockFilter:
		// 这里需要一个 socket fd，通常用于 raw socket 过滤，略作示意
		coll.Close()
		return nil, nil, errors.New("SockFilter类型需传入socket fd, 这里略过")
	case AttachCgroupSock:
		lnk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    args.Target,
			Attach:  ebpf.AttachCGroupInetSockCreate,
			Program: prog,
		})
	default:
		coll.Close()
		return nil, nil, fmt.Errorf("不支持的Attach类型: %s", args.Ebpftype)
	}

	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("挂载失败: %w", err)
	}

	return lnk, coll, nil
}

// 获取网卡信息
func netInterfaceByName(name string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface, nil
}

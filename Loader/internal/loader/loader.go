package loader

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/bearslyricattack/EBPForge/pkg"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

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

// LoadAndAttachBPF loads an eBPF object file and attaches it according to the specified arguments
func LoadAndAttachBPF(bpfObjectPath string, args pkg.AttachArgs) (link.Link, *ebpf.Collection, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove MEMLOCK limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF object file: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	prog, ok := coll.Programs[args.Program]
	if !ok {
		availableProgs := make([]string, 0, len(coll.Programs))
		for name := range coll.Programs {
			availableProgs = append(availableProgs, name)
		}
		coll.Close()
		return nil, nil, fmt.Errorf("program '%s' not found, available: %v", args.Name, availableProgs)
	}

	var lnk link.Link

	switch args.Ebpftype {
	case AttachKprobe:
		fmt.Println(1211111)
		lnk, err = link.Kprobe(args.Target, prog, nil)
	case AttachKretprobe:
		lnk, err = link.Kretprobe(args.Target, prog, nil)
	case AttachTracepoint:
		ss, ev, ok := strings.Cut(args.Target, ":")
		if !ok {
			coll.Close()
			return nil, nil, errors.New("tracepoint target format should be 'subsys:event'")
		}
		lnk, err = link.Tracepoint(ss, ev, prog, nil)
	case AttachXDP:
		iface, err2 := netInterfaceByName(args.Target)
		if err2 != nil {
			coll.Close()
			return nil, nil, fmt.Errorf("failed to get network interface: %w", err2)
		}
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
	case AttachSockFilter:
		coll.Close()
		return nil, nil, errors.New("SockFilter type requires a socket fd, skipped here")
	case AttachCgroupSock:
		lnk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    args.Target,
			Attach:  ebpf.AttachCGroupInetSockCreate,
			Program: prog,
		})
	default:
		coll.Close()
		return nil, nil, fmt.Errorf("unsupported attach type: %s", args.Ebpftype)
	}

	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("attachment failed: %w", err)
	}

	bpfFSPath := "/sys/fs/bpf"
	if err := os.MkdirAll(bpfFSPath, 0755); err != nil {
		lnk.Close()
		coll.Close()
		return nil, nil, fmt.Errorf("failed to create BPF filesystem path: %w", err)
	}

	progDir := filepath.Join(bpfFSPath, args.Name)
	if err := os.MkdirAll(progDir, 0755); err != nil {
		lnk.Close()
		coll.Close()
		return nil, nil, fmt.Errorf("failed to create program directory: %w", err)
	}

	for mapName, m := range coll.Maps {
		mapPath := filepath.Join(progDir, mapName)
		if _, err := os.Stat(mapPath); err == nil {
			if err := os.Remove(mapPath); err != nil {
				lnk.Close()
				coll.Close()
				return nil, nil, fmt.Errorf("failed to remove existing map '%s': %w", mapName, err)
			}
		}

		if err := m.Pin(mapPath); err != nil {
			lnk.Close()
			coll.Close()
			return nil, nil, fmt.Errorf("failed to pin map '%s': %w", mapName, err)
		}
		fmt.Printf("Map '%s' pinned to: %s\n", mapName, mapPath)
	}
	return lnk, coll, nil
}

func netInterfaceByName(name string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface, nil
}

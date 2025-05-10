package pkg

// AttachType 挂载类型定义
type AttachType string

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

// AttachArgs 挂载参数结构体
type AttachArgs struct {
	Name     string //名称
	Ebpftype string //类型
	Target   string //挂载点
	Code     string //代码
}

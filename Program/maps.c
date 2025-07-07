// simple_execve_monitor.c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>


//Go 结构体


// Go 结构体定义
// 用于解析从eBPF映射中读取的JSON数据
// 每个条目包含一个键（字符串类型）和一个值（数值类型）
var entries []struct {
    Key   string      `json:"key"`
    Value json.Number `json:"value"`
}


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[32]);
    __type(value, __u64);
} syscall_count SEC(".maps");



var entries []struct {
	Key   string      `json:"key"`
	Value json.Number `json:"value"`
}
// 定义map结构，用于存储不同进程的execve调用计数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[32]);       // 进程名称
    __type(value, __u64);        // 调用计数
} syscall_count SEC(".maps");


// 跟踪execve系统调用
SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
    char comm[32] = {0};
    __u64 count = 1;
    __u64 *value;

    // 获取当前进程名称
    bpf_get_current_comm(comm, sizeof(comm));

    // 查找当前进程名称的计数值
    value = bpf_map_lookup_elem(&syscall_count, &comm);
    if (value) {
        // 如果存在，增加计数
        count = *value + 1;
    }
    // 更新map中的计数值
    bpf_map_update_elem(&syscall_count, &comm, &count, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

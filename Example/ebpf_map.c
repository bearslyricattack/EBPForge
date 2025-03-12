// ebpf_kprobe.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

// 定义一个BPF map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} syscall_counts SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 zero = 0, *count;

    // 查找或初始化pid的计数
    count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (!count) {
        bpf_map_update_elem(&syscall_counts, &pid, &zero, BPF_ANY);
        count = bpf_map_lookup_elem(&syscall_counts, &pid);
        if (!count)
            return 0;
    }

    (*count)++;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
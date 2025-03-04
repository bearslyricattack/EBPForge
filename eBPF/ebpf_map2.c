// ebpf_map2.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

// 定义进程执行信息的结构体
struct exec_data {
    __u64 timestamp;         // 时间戳
    __u32 pid;               // 进程ID
    __u32 ppid;              // 父进程ID
    __u32 uid;               // 用户ID
    __u32 gid;               // 组ID
    char comm[TASK_COMM_LEN]; // 进程名
    __u64 count;             // 执行次数计数
};

// 定义一个BPF map来存储计数信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} syscall_counts SEC(".maps");

// 定义一个BPF map来存储详细的执行信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct exec_data);
} exec_details SEC(".maps");

// 定义一个环形缓冲区，用于将事件传递到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx) {
    // 获取基本进程信息
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;

    // 创建执行数据结构体
    struct exec_data data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.pid = pid;
    data.uid = uid;
    data.gid = gid;

    // 获取进程名
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 获取父进程ID (从任务结构中获取)
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        // 尝试读取父进程ID
        bpf_probe_read(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);
    }

    // 更新计数
    __u64 zero = 0, *count;
    count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (!count) {
        bpf_map_update_elem(&syscall_counts, &pid, &zero, BPF_ANY);
        count = bpf_map_lookup_elem(&syscall_counts, &pid);
        if (!count)
            return 0;
    }
    (*count)++;
    data.count = *count;

    // 更新详细信息
    bpf_map_update_elem(&exec_details, &pid, &data, BPF_ANY);

    // 向用户空间发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
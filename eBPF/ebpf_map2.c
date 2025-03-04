// ebpf_kprobe.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/fs_struct.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 128
#define MAX_ARGS_LEN 128

// 定义进程执行信息的结构体
struct exec_data {
    __u64 timestamp;         // 时间戳
    __u32 pid;               // 进程ID
    __u32 ppid;              // 父进程ID
    __u32 uid;               // 用户ID
    __u32 gid;               // 组ID
    char comm[TASK_COMM_LEN]; // 进程名
    char filepath[MAX_PATH_LEN]; // 执行文件路径
    char args[MAX_ARGS_LEN]; // 命令行参数
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

// 辅助函数：安全地获取字符串
static __always_inline int bpf_probe_read_str_safe(void *dst, size_t size, const void *unsafe_ptr) {
    int ret = bpf_probe_read_str(dst, size, unsafe_ptr);
    if (ret < 0)
        return 0;
    return ret;
}

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx) {
    // 获取基本进程信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
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

    // 获取父进程ID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent;
        bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            __u64 ppid_tgid;
            bpf_probe_read(&ppid_tgid, sizeof(ppid_tgid), &parent->tgid);
            data.ppid = ppid_tgid;
        }
    }

    // 尝试获取文件路径
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx));
    if (filename) {
        bpf_probe_read_str_safe(data.filepath, sizeof(data.filepath), filename);
    }

    // 尝试获取参数
    char **argv;
    bpf_probe_read(&argv, sizeof(argv), &PT_REGS_PARM2(ctx));
    if (argv) {
        char *arg;
        bpf_probe_read(&arg, sizeof(arg), &argv[0]);
        if (arg) {
            bpf_probe_read_str_safe(data.args, sizeof(data.args), arg);
        }
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
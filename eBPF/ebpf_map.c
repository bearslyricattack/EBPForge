// 定义一个哈希 map，键是进程 ID，值是计数器
BPF_HASH(syscall_counts, u32, u64);

int kprobe__sys_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count, zero = 0;

    // 查找或初始化 pid 的计数
    count = syscall_counts.lookup_or_init(&pid, &zero);
    (*count)++;

    return 0;
}
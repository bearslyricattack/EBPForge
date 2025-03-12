 // ebpf_map2.c
 #include <linux/bpf.h>
 #include <bpf/bpf_helpers.h>
 #include <linux/ptrace.h>

 #define TASK_COMM_LEN 16

 // 定义带有进程名的结构体
 struct proc_info {
     char comm[TASK_COMM_LEN]; // 进程名
     __u32 pid;               // 进程ID
     __u64 count;             // 执行次数计数
 };

 // 定义一个BPF map来存储进程信息
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 8192);
     __type(key, __u32);
     __type(value, struct proc_info);
 } proc_execve SEC(".maps");

 SEC("kprobe/sys_execve")
 int kprobe__sys_execve(struct pt_regs *ctx) {
     // 获取进程ID
     __u32 pid = bpf_get_current_pid_tgid() >> 32;

     // 查找或创建新的进程信息
     struct proc_info info = {0};
     struct proc_info *existing_info = bpf_map_lookup_elem(&proc_execve, &pid);

     if (existing_info) {
         // 如果记录已存在，复制内容并增加计数
         __builtin_memcpy(&info, existing_info, sizeof(info));
         info.count++;
     } else {
         // 如果是新记录，获取进程名并设置计数为1
         bpf_get_current_comm(&info.comm, sizeof(info.comm));
         info.pid = pid;
         info.count = 1;
     }

     // 更新map
     bpf_map_update_elem(&proc_execve, &pid, &info, BPF_ANY);

     return 0;
 }

 char LICENSE[] SEC("license") = "GPL";
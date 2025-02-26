// xdp_example.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{

    // 输出流量统计
    bpf_printk("");
    // 简单的XDP程序，仅通过所有数据包
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
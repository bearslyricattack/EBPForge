// xdp_example.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 定义一个简单的计数器映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_counter SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    // 计算数据包大小
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = data_end - data;

    // 更新数据包计数器
    __u32 key = 0;
    __u64 *count;
    __u64 new_count = 1;

    count = bpf_map_lookup_elem(&packet_counter, &key);
    if (count) {
        new_count = *count + 1;
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&packet_counter, &key, &new_count, BPF_ANY);
    }

    // 只打印每100个数据包的信息，避免日志过多
    if (new_count % 100 == 0) {
        bpf_printk("XDP: Processed packet #%llu, Size: %u bytes", new_count, packet_size);
    }

    // 简单的XDP程序，仅通过所有数据包
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
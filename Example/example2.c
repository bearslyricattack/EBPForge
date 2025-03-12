// minimal_traffic_monitor.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

// 使用全局变量跟踪流量
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} traffic_stats SEC(".maps");

// 用于定期输出的计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} output_counter SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 计算数据包大小
    __u64 packet_size = data_end - data;

    // 更新总流量字节计数
    __u32 bytes_key = 1;
    __u64 *bytes_count;
    bytes_count = bpf_map_lookup_elem(&traffic_stats, &bytes_key);
    if (bytes_count) {
        __sync_fetch_and_add(bytes_count, packet_size);
    } else {
        bpf_map_update_elem(&traffic_stats, &bytes_key, &packet_size, BPF_ANY);
    }

    // 更新总数据包计数
    __u32 packets_key = 0;
    __u64 *packets_count;
    packets_count = bpf_map_lookup_elem(&traffic_stats, &packets_key);
    if (packets_count) {
        __sync_fetch_and_add(packets_count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&traffic_stats, &packets_key, &initial, BPF_ANY);
    }

    // 每隔一定数量的数据包输出一次统计信息
    __u32 counter_key = 0;
    __u32 *counter = bpf_map_lookup_elem(&output_counter, &counter_key);
    if (counter && ++(*counter) >= 10000) {  // 每10000个包输出一次
        // 读取当前统计数据
        __u64 total_packets = 0;
        __u64 total_bytes = 0;

        if (packets_count) total_packets = *packets_count;
        if (bytes_count) total_bytes = *bytes_count;

        // 输出流量统计
        bpf_printk("Traffic stats: %llu packets, %llu bytes",
                   total_packets, total_bytes);

        // 重置计数器
        *counter = 0;
    }

    // 允许数据包通过
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
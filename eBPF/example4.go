package eBPF

// 简单的BPF程序示例
const SampleBPFProgram = `
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

// 这是一个简单的BPF程序，它会计数所有经过的IP包
int count_ip_packets(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 检查数据是否足够包含以太网头部
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    
    // 检查是否是IP包
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        // 这里只是简单返回，实际应用中可能会更新某个映射(map)来计数
        return TC_ACT_OK;
    }
    
    return TC_ACT_OK;
}
`

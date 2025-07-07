# 基于Kubernetes Operator的公有云可观测工具

一个基于Kubernetes Operator和eBPF技术的公有云可观测工具。

## 项目概述

本项目设计并实现了一个基于Kubernetes Operator的公有云可观测工具，通过结合eBPF技术与Prometheus和Grafana等云原生可观测领域的基础设施，实现深度系统监控和性能分析。系统主要由三个功能模块组成：

- **Kubernetes Operator**：负责在集群维度上配置和部署相关组件，根据用户配置动态调用其他组件完成部署
- **内核加载模块**：负责对eBPF代码进行编译，加载进入Linux内核并挂载数据到文件系统
- **数据转发模块**：负责读取文件系统上的eBPF代码输出，并定时转发到Prometheus

## 功能特性

- 无侵入式监控：无需修改应用代码，直接从内核层面获取性能数据
- 声明式配置：通过Kubernetes CRD实现eBPF程序的声明式管理
- 自动化部署：自动完成eBPF程序的编译、加载和数据收集配置
- 多租户支持：在多租户环境下实现资源的有效监控和管理，确保租户间数据隔离
- 实时监控：从Linux系统内核获取程序运行的相关信息，提供实时性能数据
- 可视化展示：与Prometheus和Grafana集成，提供直观的监控数据可视化

## 系统架构

![image-20250707111136003](https://bearsblog.oss-cn-beijing.aliyuncs.com/img/image-20250707111136003.png)

系统采用三层架构设计：

1. **控制层**：Kubernetes Operator负责接收和处理用户通过CR提交的eBPF程序配置
2. **执行层**：内核加载模块和数据转发模块分布在各节点上，执行eBPF程序的加载和数据收集
3. **存储与展示层**：Prometheus负责数据存储，Grafana负责数据可视化展示

## 快速开始

### 前提条件

- Kubernetes集群 v1.16+
- Linux内核 4.18+（支持eBPF功能）
- 已安装Helm v3
- 节点上已安装Clang和Linux内核头文件

### 安装步骤

1.安装Prometheus和Grafana

```bash
bashhelm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace
```

2.安装Operator

```bash
bashkubectl apply -f https://raw.githubusercontent.com/username/ebpf-operator/main/deploy/operator.yaml
```

3.创建一个示例eBPF监控

```bash
bashcat <<EOF | kubectl apply -f -
apiVersion: observability.cloud/v1
kind: EbpfMap
metadata:
  name: syscall-monitor
spec:
  name: syscall-counter
  target: sys_execve
  type: kprobe
  program: count_execve
  help: "Count of execve syscalls"
  prometheusType: counter
  map: execve_count
  code: |
    #include <linux/bpf.h>
    #include <linux/ptrace.h>
    #include <bpf/bpf_helpers.h>
    
    struct {
      __uint(type, BPF_MAP_TYPE_HASH);
      __uint(max_entries, 1);
      __type(key, u32);
      __type(value, u64);
    } execve_count SEC(".maps");
    
    SEC("kprobe/sys_execve")
    int count_execve(struct pt_regs *ctx) {
      u32 key = 0;
      u64 *val, init_val = 1;
      
      val = bpf_map_lookup_elem(&execve_count, &key);
      if (val) {
        (*val)++;
      } else {
        bpf_map_update_elem(&execve_count, &key, &init_val, BPF_ANY);
      }
      return 0;
    }
    
    char LICENSE[] SEC("license") = "GPL";
EOF
```

4.检查部署状态

```bash
bashkubectl get ebpfmap
kubectl describe ebpfmap syscall-monitor
```

5.在Grafana中查看监控数据

访问Grafana界面（默认用户名/密码：admin/prom-operator），创建新的Dashboard并添加查询：`syscall_counter_total`

## 自定义资源定义

系统定义了`EbpfMap` CRD，用于配置和管理eBPF程序。主要字段包括：

- `name`: eBPF代码的名称
- `target`: eBPF代码部署的挂载点
- `type`: eBPF代码的类型（如kprobe, tracepoint, xdp等）
- `code`: eBPF具体的代码内容
- `program`: eBPF程序内部定义的名称
- `help`: Prometheus帮助文本中显示的内容
- `prometheusType`: Prometheus中使用的指标类型（如counter、gauge等）
- `map`: eBPF Maps的具体名称

## 支持的eBPF程序类型

| 名称         | 类型       | 描述                     | 挂载点举例                           |
| ------------ | ---------- | ------------------------ | ------------------------------------ |
| Kprobe       | kprobe     | 跟踪内核函数的入口点     | kprobe/sys_execve                    |
| Kretprobe    | kretprobe  | 跟踪内核函数的返回点     | kretprobe/sys_execve                 |
| Tracepoint   | tracepoint | 内核中预定义的静态点     | tracepoint/syscalls/sys_enter_execve |
| XDP          | xdp        | 用于高性能网络处理       | xdp/eth0                             |
| 套接字过滤器 | socket     | 附加到套接字上           | sockfilter/eth0                      |
| Cgroup       | cgroup     | 用于基于cgroup的网络控制 | cgroup/skb                           |

## 应用场景

- 云原生应用监控：深入监控容器化应用的系统调用、网络流量和资源使用情况
- 多租户环境下的资源管理：在共享基础设施上实现租户间的资源隔离和监控
- 系统故障诊断与快速恢复：通过内核级监控数据快速定位性能瓶颈和异常行为

## 贡献指南

欢迎贡献代码、报告问题或提出新功能建议！请遵循以下步骤：

1. Fork本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启一个Pull Request

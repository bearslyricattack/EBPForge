/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EbpfMapSpec defines the desired state of EbpfMap.
type EbpfMapSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	//ebpf代码的名称
	Name string `json:"name,omitempty"`

	//ebpf 代码部署的挂载点
	Target string `json:"target,omitempty"`

	//ebpf 代码的类型
	Type string `json:"type,omitempty"`

	//ebpf 具体的代码
	Code string `json:"code,omitempty"`

	//ebpf 程序里写的名称
	Program string `json:"program,omitempty"`

	//ebpf 在prometheus-help中的内容
	Help string `json:"help,omitempty"`

	//ebpf 在prometheus-type中的类型
	PrometheusType string `json:"prometheusType,omitempty"`

	//ebpf maps 具体的名称
	Map string `json:"map,omitempty"`
}

// EbpfMapStatus defines the observed state of EbpfMap.
type EbpfMapStatus struct {

	// Conditions 表示 EbpfMap 资源的当前状态条件列表
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// Phase 表示 EbpfMap 资源的整体状态
	// 可能的值: Pending, Deploying, Running, Failed, Terminating
	// +optional
	Phase string `json:"phase,omitempty"`

	// MountStatus 表示 eBPF 程序挂载的状态
	// +optional
	MountStatus string `json:"mountStatus,omitempty"`

	// ForwardingStatus 表示 eBPF 数据转发程序的运行状态
	// +optional
	ForwardingStatus string `json:"forwardingStatus,omitempty"`

	// RunningNodes 表示当前运行 eBPF 程序的节点列表
	// +optional
	RunningNodes []string `json:"runningNodes,omitempty"`

	// NodeCount 表示当前运行 eBPF 程序的节点总数
	// +optional
	NodeCount int32 `json:"nodeCount,omitempty"`

	// LastSuccessfulUpdate 记录最后一次成功更新的时间戳
	// +optional
	LastSuccessfulUpdate metav1.Time `json:"lastSuccessfulUpdate,omitempty"`

	// Metrics 记录 eBPF 程序收集的关键指标摘要
	// +optional
	Metrics map[string]string `json:"metrics,omitempty"`

	// ErrorMessage 记录最近的错误信息，如果有的话
	// +optional
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EbpfMap is the Schema for the ebpfmaps API.
type EbpfMap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EbpfMapSpec   `json:"spec,omitempty"`
	Status EbpfMapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EbpfMapList contains a list of EbpfMap.
type EbpfMapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EbpfMap `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EbpfMap{}, &EbpfMapList{})
}

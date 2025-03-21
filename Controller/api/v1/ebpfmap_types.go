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

	// Foo is an example field of EbpfMap. Edit ebpfmap_types.go to remove/update
	Foo string `json:"foo,omitempty"`

	// 代码的位置 - Location of the code
	CodeLocation string `json:"codeLocation,omitempty"`

	// 程序的名称 - Name of the program
	ProgramName string `json:"programName,omitempty"`

	// 程序的类型 - Type of the program
	ProgramType string `json:"programType,omitempty"`
}

// EbpfMapStatus defines the observed state of EbpfMap.
type EbpfMapStatus struct {

	// Conditions 表示 EbpfMap 资源的当前状态条件列表
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
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

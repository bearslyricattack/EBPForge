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

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"io/ioutil"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"net/http"
	"net/url"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"sync"
	"time"

	ebpfv1 "github.com/bearslyricattack/ebpf-controller/api/v1"
)

// EbpfMapReconciler reconciles a EbpfMap object
type EbpfMapReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ebpf.github.com,resources=ebpfmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ebpf.github.com,resources=ebpfmaps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ebpf.github.com,resources=ebpfmaps/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EbpfMap object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.0/pkg/reconcile
// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// Reconcile 是 Kubernetes 协调循环的一部分，旨在使集群的当前状态更接近期望状态。
func (r *EbpfMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 获取 EbpfMap 实例
	var ebpfMap ebpfv1.EbpfMap
	if err := r.Get(ctx, req.NamespacedName, &ebpfMap); err != nil {
		if k8serror.IsNotFound(err) {
			// 请求的对象不存在，可能已被删除
			logger.Info("未找到 EbpfMap 资源，忽略，因为它可能已被删除")
			return ctrl.Result{}, nil
		}
		// 获取对象时出错 - 重新入队请求
		logger.Error(err, "获取 EbpfMap 失败")
		return ctrl.Result{RequeueAfter: time.Second * 10}, err
	}

	// 如果尚未设置状态，则初始化状态
	if ebpfMap.Status.Phase == "" {
		ebpfMap.Status.Phase = "Pending"
		ebpfMap.Status.MountStatus = "NotMounted"
		ebpfMap.Status.ForwardingStatus = "NotStarted"
		ebpfMap.Status.NodeCount = 0
		ebpfMap.Status.RunningNodes = []string{}
		return r.updateStatus(ctx, &ebpfMap, logger)
	}

	// 更新状态以表明部署正在进行中
	ebpfMap.Status.Phase = "Deploying"
	_, err := r.updateStatus(ctx, &ebpfMap, logger)
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 10}, err
	}

	// 构建并调用列表中的多个 URL
	urls := []string{
		"http://192.168.0.53:8082/load",
		"http://192.168.10.63:8082/load",
		// 根据需要添加更多 URL
	}

	successCount := 0
	totalURLs := len(urls)
	successfulNodes := []string{}
	for _, baseURL := range urls {
		// 从 URL 中提取节点标识符（演示用，使用 IP）
		nodeID := baseURL[7:] // 移除 "http://" 前缀
		nodeID = nodeID[:strings.Index(nodeID, ":")]
		// 为每个基础 URL 构建包含所有必需参数的 URL
		URL := fmt.Sprintf("%s?name=%s&target=%s&type=%s&code=%s&program=%s", baseURL, url.QueryEscape(ebpfMap.Spec.Name), url.QueryEscape(ebpfMap.Spec.Target), url.QueryEscape(ebpfMap.Spec.Type), url.QueryEscape(ebpfMap.Spec.Code), url.QueryEscape(ebpfMap.Spec.Program))
		fmt.Println(URL)
		// 发送 HTTP 请求
		resp, err := http.Get(URL)
		if err != nil {
			logger.Error(err, "向 "+baseURL+" 发送 HTTP 请求失败")
			// 继续下一个 URL
			continue
		}
		// 读取响应体
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close() // 在循环中关闭响应体
		if err != nil {
			logger.Error(err, "从 "+baseURL+" 读取响应体失败")
			continue
		}
		// 处理响应
		logger.Info("收到响应", "baseURL", baseURL, "response", string(body))
		// 统计成功的请求
		if resp.StatusCode == http.StatusOK {
			successCount++
			successfulNodes = append(successfulNodes, nodeID)
		}
	}

	// 根据成功计数更新挂载状态
	if successCount > 0 {
		ebpfMap.Status.MountStatus = "Mounted"
	} else {
		ebpfMap.Status.MountStatus = "MountFailed"
		ebpfMap.Status.Phase = "Failed"
		ebpfMap.Status.ErrorMessage = "在任何节点上挂载 eBPF 程序失败"
		logger.Error(err, "在任何节点上挂载 eBPF 程序失败")
		return r.updateStatus(ctx, &ebpfMap, logger)
	}

	// 更新状态以表明程序已加载
	condition := metav1.Condition{
		Type:               "Loaded",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "CurlSuccess",
		Message:            fmt.Sprintf("成功在 %d/%d 个节点上加载 eBPF 程序", successCount, totalURLs),
	}
	meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)

	// 注册端点的 URL
	registerURLs := []string{
		"http://192.168.0.53:8080/register",
		"http://192.168.10.63:8080/register",
		// 根据需要添加更多 URL
	}

	registerSuccessCount := 0
	totalRegisterURLs := len(registerURLs)
	forwardingNodes := []string{}

	// 准备 JSON 负载
	registerPayload := map[string]interface{}{
		"name":   ebpfMap.Spec.Name,
		"help":   ebpfMap.Spec.Help,
		"type":   ebpfMap.Spec.PrometheusType,
		"labels": []string{"key"},
		"path":   "/sys/fs/bpf/" + ebpfMap.Spec.Name + "/" + ebpfMap.Spec.Map,
	}

	// 将负载转换为 JSON
	jsonPayload, err := json.Marshal(registerPayload)
	if err != nil {
		logger.Error(err, "序列化 JSON 负载失败")
		ebpfMap.Status.ErrorMessage = "为注册序列化 JSON 负载失败"
		return r.updateStatus(ctx, &ebpfMap, logger)
	}

	for _, registerURL := range registerURLs {
		// 从 URL 中提取节点标识符
		nodeID := registerURL[7:] // 移除 "http://" 前缀
		nodeID = nodeID[:strings.Index(nodeID, ":")]

		// 创建新的 POST 请求
		req, err := http.NewRequest("POST", registerURL, bytes.NewBuffer(jsonPayload))
		if err != nil {
			logger.Error(err, "为 "+registerURL+" 创建 HTTP 请求失败")
			continue
		}

		// 设置头部
		req.Header.Set("Content-Type", "application/json")

		// 发送请求
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			logger.Error(err, "向 "+registerURL+" 发送 HTTP 请求失败")
			continue
		}

		// 读取响应体
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close() // 在循环中关闭响应体

		if err != nil {
			logger.Error(err, "从 "+registerURL+" 读取响应体失败")
			continue
		}

		// 处理响应
		logger.Info("收到注册响应", "registerURL", registerURL, "response", string(body))

		// 统计成功的请求
		if resp.StatusCode == http.StatusOK {
			registerSuccessCount++
			forwardingNodes = append(forwardingNodes, nodeID)
		}
	}

	// 根据成功计数更新转发状态
	if registerSuccessCount > 0 {
		ebpfMap.Status.ForwardingStatus = "Active"
	} else {
		ebpfMap.Status.ForwardingStatus = "Failed"
		ebpfMap.Status.ErrorMessage = "在任何节点上注册指标转发失败"
	}

	// 更新最终状态
	ebpfMap.Status.RunningNodes = successfulNodes
	ebpfMap.Status.NodeCount = int32(len(successfulNodes))
	ebpfMap.Status.LastSuccessfulUpdate = metav1.Now()

	// 如果尚未设置，则初始化指标映射
	if ebpfMap.Status.Metrics == nil {
		ebpfMap.Status.Metrics = make(map[string]string)
	}
	ebpfMap.Status.Metrics["mountSuccess"] = fmt.Sprintf("%d/%d", successCount, totalURLs)
	ebpfMap.Status.Metrics["forwardingSuccess"] = fmt.Sprintf("%d/%d", registerSuccessCount, totalRegisterURLs)

	// 根据整体成功情况设置最终阶段
	if successCount > 0 && registerSuccessCount > 0 {
		ebpfMap.Status.Phase = "Running"
		condition = metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "DeploymentComplete",
			Message:            "eBPF 程序正在运行并转发指标",
		}
	} else if successCount > 0 {
		ebpfMap.Status.Phase = "PartiallyRunning"
		condition = metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "ForwardingFailed",
			Message:            "eBPF 程序已挂载但指标转发失败",
		}
	} else {
		ebpfMap.Status.Phase = "Failed"
		condition = metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "DeploymentFailed",
			Message:            "部署 eBPF 程序失败",
		}
	}
	meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)

	// 更新状态
	_, err = r.updateStatus(ctx, &ebpfMap, logger)
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 10}, err
	}

	logger.Info("协调完成",
		"phase", ebpfMap.Status.Phase,
		"mountSuccess", fmt.Sprintf("%d/%d", successCount, totalURLs),
		"forwardingSuccess", fmt.Sprintf("%d/%d", registerSuccessCount, totalRegisterURLs))

	// 如果不完全成功，则重新入队
	if ebpfMap.Status.Phase != "Running" {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute * 5}, nil
	}
	return ctrl.Result{}, nil
}

// 存储最近处理的资源版本和重试次数
var (
	processedVersions = make(map[string]string)
	retryCount        = make(map[string]int)
	maxRetries        = 5
	statusUpdateMutex sync.Mutex
)

// 统一的状态更新辅助函数 - 仅输出日志，不执行实际更新
func (r *EbpfMapReconciler) updateStatus(ctx context.Context, ebpfMap *ebpfv1.EbpfMap, logger logr.Logger) (ctrl.Result, error) {
	// 创建资源键，用于日志标识
	key := fmt.Sprintf("%s/%s", ebpfMap.Namespace, ebpfMap.Name)

	// 记录状态变更的日志信息
	logger.Info("状态更新函数被调用 (仅日志记录，不执行实际更新)",
		"resource", key,
		"resourceVersion", ebpfMap.ResourceVersion,
		"status", ebpfMap.Status)

	// 返回正常结果，不进行重新排队
	return ctrl.Result{}, nil
}

//// 统一的状态更新辅助函数
//func (r *EbpfMapReconciler) updateStatus(ctx context.Context, ebpfMap *ebpfv1.EbpfMap, logger logr.Logger) (ctrl.Result, error) {
//	// 使用互斥锁保护共享映射访问
//	statusUpdateMutex.Lock()
//	defer statusUpdateMutex.Unlock()
//
//	// 创建资源键
//	key := fmt.Sprintf("%s/%s", ebpfMap.Namespace, ebpfMap.Name)
//
//	// 检查是否是相同的资源版本
//	if lastVersion, exists := processedVersions[key]; exists && lastVersion == ebpfMap.ResourceVersion {
//		// 增加重试计数
//		retryCount[key]++
//
//		// 如果超过最大重试次数，则暂停较长时间
//		if retryCount[key] > maxRetries {
//			logger.Info("达到最大重试次数，延长等待时间",
//				"resource", key,
//				"retries", retryCount[key])
//
//			// 重置重试计数器
//			retryCount[key] = 0
//
//			// 返回较长的重新排队时间
//			return ctrl.Result{RequeueAfter: time.Minute * 5}, nil
//		}
//
//		// 根据重试次数增加等待时间
//		waitTime := time.Second * time.Duration(5*retryCount[key])
//		logger.Info("检测到相同资源版本，增加等待时间",
//			"resource", key,
//			"retries", retryCount[key],
//			"waitTime", waitTime)
//
//		return ctrl.Result{RequeueAfter: waitTime}, nil
//	}
//
//	// 记录当前处理的资源版本
//	processedVersions[key] = ebpfMap.ResourceVersion
//	retryCount[key] = 0
//
//	// 尝试更新状态
//	err := r.Status().Update(ctx, ebpfMap)
//	if err != nil {
//		if apierrors.IsConflict(err) {
//			logger.Info("检测到资源冲突，延迟后重新排队", "resource", key)
//			return ctrl.Result{RequeueAfter: time.Second * 3}, nil
//		}
//
//		// 处理速率限制错误
//		if strings.Contains(err.Error(), "rate limiter") {
//			logger.Info("API 速率限制，稍后重试", "error", err, "resource", key)
//			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
//		}
//
//		// 处理上下文取消
//		if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled") {
//			logger.Info("上下文已取消，延迟后重新排队", "error", err, "resource", key)
//			return ctrl.Result{RequeueAfter: time.Second * 5}, nil
//		}
//
//		// 其他可能是临时性的错误
//		logger.Error(err, "更新 EbpfMap 状态失败", "resource", key)
//		return ctrl.Result{RequeueAfter: time.Second * 15}, nil
//	}
//
//	logger.Info("成功更新状态", "resource", key, "resourceVersion", ebpfMap.ResourceVersion)
//	return ctrl.Result{RequeueAfter: time.Second * 10}, nil
//}

// SetupWithManager sets up the controller with the Manager.
func (r *EbpfMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebpfv1.EbpfMap{}).
		Named("ebpfmap").
		Complete(r)
}

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
	"context"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

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
func (r *EbpfMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 获取 EbpfMap 实例
	var ebpfMap ebpfv1.EbpfMap
	if err := r.Get(ctx, req.NamespacedName, &ebpfMap); err != nil {
		if errors.IsNotFound(err) {
			// 请求的对象不存在，可能已被删除
			// 返回并且不重新排队
			logger.Info("EbpfMap 资源未找到，忽略，因为对象可能已被删除")
			return ctrl.Result{}, nil
		}
		// 读取对象时出错 - 重新排队请求
		logger.Error(err, "获取 EbpfMap 失败")
		return ctrl.Result{}, err
	}

	// 通过检查状态或注解确认这是否是新的 CR
	// 这是一种简化的方法 - 您可能需要使用更健壮的方法
	// 比如使用终结器或适当的状态管理
	if ebpfMap.Status.Conditions == nil || len(ebpfMap.Status.Conditions) == 0 {
		logger.Info("检测到新的 EbpfMap CR，触发 curl 请求")
		// 构建带有路径和名称参数的 URL
		baseURL := "http://192.168.0.53:8082/load"
		path := ebpfMap.Spec.CodeLocation
		name := ebpfMap.Spec.ProgramName
		url := fmt.Sprintf("%s?path=%s&name=%s", baseURL, path, name)
		// 发送 HTTP 请求
		resp, err := http.Get(url)
		if err != nil {
			logger.Error(err, "发送 HTTP 请求失败")
			return ctrl.Result{RequeueAfter: time.Minute}, err
		}
		defer resp.Body.Close()

		// 读取响应体
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Error(err, "读取响应体失败")
			return ctrl.Result{RequeueAfter: time.Minute}, err
		}

		// 检查响应状态
		if resp.StatusCode != http.StatusOK {
			logger.Error(nil, "服务器返回非 OK 响应",
				"状态码", resp.StatusCode,
				"响应体", string(body))
			return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("非 OK 响应: %d", resp.StatusCode)
		}

		logger.Info("成功加载 Example 程序",
			"状态码", resp.StatusCode,
			"响应", string(body))

		// 更新状态以表明程序已加载
		// 这可以防止在后续协调中重新触发 curl
		condition := metav1.Condition{
			Type:               "Loaded",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "CurlSuccess",
			Message:            "成功加载 Example 程序",
		}

		meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)

		if err := r.Status().Update(ctx, &ebpfMap); err != nil {
			logger.Error(err, "更新 EbpfMap 状态失败")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EbpfMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebpfv1.EbpfMap{}).
		Named("ebpfmap").
		Complete(r)
}

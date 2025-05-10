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
	"k8s.io/apimachinery/pkg/runtime"
	"net/http"
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

	// Retrieve the EbpfMap instance
	var ebpfMap ebpfv1.EbpfMap
	if err := r.Get(ctx, req.NamespacedName, &ebpfMap); err != nil {
		if errors.IsNotFound(err) {
			// The requested object does not exist, possibly deleted
			logger.Info("EbpfMap resource not found, ignoring since it may have been deleted")
			return ctrl.Result{}, nil
		}
		// Error while retrieving the object - requeue the request
		logger.Error(err, "Failed to fetch EbpfMap")
		return ctrl.Result{}, err
	}

	// Check if this is a new Custom Resource (CR)
	if len(ebpfMap.Status.Conditions) == 0 {
		logger.Info("New EbpfMap CR detected, triggering curl request")

		// Construct and call multiple URLs from a list
		urls := []string{
			"http://192.168.0.53:8082/load",
			"http://192.168.10.63:8082/load",
			// Add more URLs as needed
		}
		for _, baseURL := range urls {
			// Construct URL with all required parameters for each base URL
			url := fmt.Sprintf("%s?name=%s&target=%s&type=%s&code=%s&program=%s", baseURL, ebpfMap.Spec.Name, ebpfMap.Spec.Target, ebpfMap.Spec.Type, ebpfMap.Spec.Code, ebpfMap.Spec.Program)
			// Send HTTP request
			resp, err := http.Get(url)
			if err != nil {
				logger.Error(err, "Failed to send HTTP request to "+baseURL)
				// Continue to next URL instead of returning immediately
				continue
			}
			// Read response body
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close() // Use this instead of defer in a loop
			if err != nil {
				logger.Error(err, "Failed to read response body from "+baseURL)
				continue
			}
			// Process the response
			logger.Info("Received response", "baseURL", baseURL, "response", string(body))
			// If you need to return after a successful request, you can do it here
			if resp.StatusCode == http.StatusOK {
				// Success case handling
				return ctrl.Result{}, nil
			}
		}

		// Update status to indicate the program has been loaded
		condition := metav1.Condition{
			Type:               "Loaded",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "CurlSuccess",
			Message:            "Successfully loaded eBPF program",
		}
		meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)

		if err := r.Status().Update(ctx, &ebpfMap); err != nil {
			logger.Error(err, "Failed to update EbpfMap status")
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

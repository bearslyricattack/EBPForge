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
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	ebpfv1 "github.com/bearslyricattack/ebpf-controller/api/v1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Constants for the controller
const (
	maxRetries              = 5
	conditionTypeLoaded     = "Loaded"
	conditionTypeRegistered = "Registered"
)

// EbpfMapReconciler reconciles a EbpfMap object
type EbpfMapReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Configuration that could be injected
	LoadURLs     []string
	RegisterURLs []string
	// Cache for tracking retries
	processedVersions map[string]string
	retryCount        map[string]int
	mutex             sync.Mutex
}

// Initialize creates a new EbpfMapReconciler with default values
func NewEbpfMapReconciler(client client.Client, scheme *runtime.Scheme) *EbpfMapReconciler {
	return &EbpfMapReconciler{
		Client: client,
		Scheme: scheme,
		LoadURLs: []string{
			"http://192.168.0.53:8082/load",
			"http://192.168.10.63:8082/load",
		},
		RegisterURLs: []string{
			"http://192.168.0.53:8080/register",
			"http://192.168.10.63:8080/register",
		},
		processedVersions: make(map[string]string),
		retryCount:        make(map[string]int),
	}
}

// Reconcile handles the reconciliation logic for EbpfMap resources
func (r *EbpfMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("ebpfMap", req.NamespacedName.String())
	logger.Info("Reconciling EbpfMap")

	// Retrieve the EbpfMap instance
	var ebpfMap ebpfv1.EbpfMap
	if err := r.Get(ctx, req.NamespacedName, &ebpfMap); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Resource not found, may have been deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to fetch resource")
		return ctrl.Result{}, err
	}
	loadResult, err := r.processEbpfLoading(ctx, &ebpfMap, logger)
	if err != nil {
		return loadResult, err
	}
	registerResult, err := r.processMetricRegistration(ctx, &ebpfMap, logger)
	if err != nil {
		return registerResult, err
	}
	if err := r.Status().Update(ctx, &ebpfMap); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{Requeue: true}, err
	}
	logger.Info("Reconciliation completed successfully")
	return ctrl.Result{}, nil
}

// processEbpfLoading handles the loading of eBPF programs
func (r *EbpfMapReconciler) processEbpfLoading(ctx context.Context, ebpfMap *ebpfv1.EbpfMap, logger logr.Logger) (ctrl.Result, error) {
	logger.Info("Starting eBPF program loading", "targets", len(r.LoadURLs))
	successCount := 0
	totalURLs := len(r.LoadURLs)
	// Use a WaitGroup to process requests concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, baseURL := range r.LoadURLs {
		wg.Add(1)
		go func(index int, loadURL string) {
			defer wg.Done()
			host := extractHostFromURL(loadURL)
			urlLogger := logger.WithValues("host", host, "index", index+1, "total", totalURLs)
			// Construct URL with parameters
			fullURL := fmt.Sprintf("%s?name=%s&target=%s&type=%s&code=%s&program=%s",
				loadURL,
				url.QueryEscape(ebpfMap.Spec.Name),
				url.QueryEscape(ebpfMap.Spec.Target),
				url.QueryEscape(ebpfMap.Spec.Type),
				url.QueryEscape(ebpfMap.Spec.Code),
				url.QueryEscape(ebpfMap.Spec.Program))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
			if err != nil {
				urlLogger.Error(err, "Failed to create request")
				return
			}
			client := &http.Client{Timeout: 10 * time.Second}
			urlLogger.V(1).Info("Sending load request")
			resp, err := client.Do(req)
			if err != nil {
				urlLogger.Error(err, "Failed to send load request")
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				urlLogger.Error(err, "Failed to read response")
				return
			}
			responseStatus := resp.StatusCode
			responseLength := len(body)
			urlLogger.Info("Received load response",
				"status", responseStatus,
				"bodySize", responseLength)
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				successCount++
				mu.Unlock()
				urlLogger.Info("Load successful")
			} else {
				urlLogger.Info("Load failed", "statusCode", resp.StatusCode, "response", string(body))
			}
		}(i, baseURL)
	}
	wg.Wait()
	condition := metav1.Condition{
		Type:               conditionTypeLoaded,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "LoadSuccess",
		Message:            fmt.Sprintf("Successfully loaded eBPF program on %d/%d targets", successCount, totalURLs),
	}
	meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)
	logger.Info("Load processing complete",
		"successCount", successCount,
		"totalURLs", totalURLs)
	if successCount == 0 {
		return ctrl.Result{Requeue: true}, fmt.Errorf("failed to process any load requests successfully")
	}
	return ctrl.Result{}, nil
}

// processMetricRegistration handles the registration of metrics
func (r *EbpfMapReconciler) processMetricRegistration(ctx context.Context, ebpfMap *ebpfv1.EbpfMap, logger logr.Logger) (ctrl.Result, error) {
	logger.Info("Starting metric registration", "targets", len(r.RegisterURLs))

	registerSuccessCount := 0
	totalRegisterURLs := len(r.RegisterURLs)
	registerPayload := map[string]interface{}{
		"name":   ebpfMap.Spec.Name,
		"help":   ebpfMap.Spec.Help,
		"type":   ebpfMap.Spec.PrometheusType,
		"labels": []string{"key"},
		"path":   "/sys/fs/bpf/" + ebpfMap.Spec.Name + "/" + ebpfMap.Spec.Map,
	}

	// Convert the payload to JSON
	jsonPayload, err := json.Marshal(registerPayload)
	if err != nil {
		logger.Error(err, "Failed to marshal JSON payload")
		return ctrl.Result{Requeue: true}, err
	}

	// Use a WaitGroup to process requests concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex // Mutex to protect registerSuccessCount

	for i, registerURL := range r.RegisterURLs {
		wg.Add(1)
		go func(index int, regURL string) {
			defer wg.Done()

			host := extractHostFromURL(regURL)
			urlLogger := logger.WithValues("host", host, "index", index+1, "total", totalRegisterURLs)

			urlLogger.V(1).Info("Sending register request")

			// Create a new POST request with context
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewBuffer(jsonPayload))
			if err != nil {
				urlLogger.Error(err, "Failed to create register request")
				return
			}

			// Set headers
			req.Header.Set("Content-Type", "application/json")

			// Send the request with timeout
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				urlLogger.Error(err, "Failed to send register request")
				return
			}
			defer resp.Body.Close()

			// Read response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				urlLogger.Error(err, "Failed to read register response")
				return
			}

			// Process the response
			responseStatus := resp.StatusCode
			responseLength := len(body)
			urlLogger.Info("Received register response", "status", responseStatus, "bodySize", responseLength)

			// Count successful requests
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				registerSuccessCount++
				mu.Unlock()
				urlLogger.Info("Registration successful")
			} else {
				urlLogger.Info("Registration failed", "statusCode", resp.StatusCode, "response", string(body))
			}
		}(i, registerURL)
	}
	// Wait for all requests to complete
	wg.Wait()
	// Update status to indicate registration status
	condition := metav1.Condition{
		Type:               conditionTypeRegistered,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "RegisterSuccess",
		Message:            fmt.Sprintf("Successfully registered metrics on %d/%d targets", registerSuccessCount, totalRegisterURLs),
	}
	meta.SetStatusCondition(&ebpfMap.Status.Conditions, condition)
	logger.Info("Registration processing complete",
		"successCount", registerSuccessCount,
		"totalURLs", totalRegisterURLs)

	if registerSuccessCount == 0 {
		return ctrl.Result{Requeue: true}, fmt.Errorf("failed to process any registration requests successfully")
	}
	return ctrl.Result{}, nil
}

// Helper function to extract host from URL for cleaner logging
func extractHostFromURL(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsedURL.Host
}

// SetupWithManager sets up the controller with the Manager.
func (r *EbpfMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebpfv1.EbpfMap{}).
		Named("ebpfmap").
		Complete(r)
}

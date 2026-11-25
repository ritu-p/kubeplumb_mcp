// Package kube builds the Kubernetes client the server uses.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient returns a clientset for the given kubeconfig and context.
//
// Empty arguments mean "use the defaults": the KUBECONFIG environment
// variable or ~/.kube/config, and that file's current context. When no
// kubeconfig is found, client-go falls back to the in-cluster service account,
// so the same binary works on a laptop and inside a pod.
func NewClient(kubeconfig, kubeContext, userAgent string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config: %w", err)
	}
	cfg.UserAgent = userAgent
	// Keep the server a polite API client; diagnosis is a handful of reads.
	cfg.QPS = 20
	cfg.Burst = 40

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return cs, nil
}

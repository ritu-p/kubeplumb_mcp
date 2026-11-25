package diagnose

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// CheckService verifies that a Service is wired to at least one ready backend.
//
// It walks the same chain kube-proxy depends on: the Service exists, exposes
// the requested port, its selector matches pods, those pods are Ready, named
// targetPorts resolve, and the EndpointSlices contain ready endpoints.
// port may be 0 to check every port the Service exposes.
//
// A non-nil error means the check itself could not run (for example the API
// call was forbidden); a diagnosed problem is returned as a blocked Result.
func CheckService(ctx context.Context, cs kubernetes.Interface, namespace, name string, port int) (Result, error) {
	svc, err := cs.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepService,
			Reason:       fmt.Sprintf("Service %s/%s does not exist.", namespace, name),
			SuggestedFix: "Check the service name and namespace the client is using.",
		}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("get service %s/%s: %w", namespace, name, err)
	}
	svcRef := Evidence{Kind: "Service", Namespace: namespace, Name: name}

	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		svcRef.Detail = "externalName: " + svc.Spec.ExternalName
		return Result{
			Verdict:  VerdictInconclusive,
			Reason:   fmt.Sprintf("Service %s/%s is of type ExternalName, so it has no in-cluster endpoints to check.", namespace, name),
			Evidence: []Evidence{svcRef},
		}, nil
	}

	ports := svc.Spec.Ports
	if port != 0 {
		ports = nil
		for _, p := range svc.Spec.Ports {
			if int(p.Port) == port {
				ports = append(ports, p)
			}
		}
		if len(ports) == 0 {
			svcRef.Detail = "exposes ports: " + describePorts(svc.Spec.Ports)
			return Result{
				Verdict:      VerdictBlocked,
				FailedStep:   StepService,
				Reason:       fmt.Sprintf("Service %s/%s does not expose port %d.", namespace, name, port),
				Evidence:     []Evidence{svcRef},
				SuggestedFix: "Connect to one of the exposed ports, or add the port to the Service spec.",
			}, nil
		}
	}

	var warnings []string

	if len(svc.Spec.Selector) == 0 {
		warnings = append(warnings, "Service has no selector, so its endpoints are managed manually or by another controller.")
	} else {
		selector := labels.SelectorFromSet(svc.Spec.Selector).String()
		svcRef.Detail = "selector: " + selector

		podList, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return Result{}, fmt.Errorf("list pods for service %s/%s: %w", namespace, name, err)
		}
		var live, ready []corev1.Pod
		for _, p := range podList.Items {
			if p.DeletionTimestamp != nil {
				continue
			}
			live = append(live, p)
			if isPodReady(&p) {
				ready = append(ready, p)
			}
		}

		if len(live) == 0 {
			return Result{
				Verdict:      VerdictBlocked,
				FailedStep:   StepService,
				Reason:       fmt.Sprintf("The selector of Service %s/%s matches no pods.", namespace, name),
				Evidence:     []Evidence{svcRef},
				SuggestedFix: fmt.Sprintf("Compare the selector with the pod labels: kubectl get pods -n %s --show-labels", namespace),
			}, nil
		}

		if len(ready) == 0 {
			evidence := []Evidence{svcRef}
			for _, p := range live {
				if len(evidence) >= maxEvidence {
					break
				}
				evidence = append(evidence, Evidence{Kind: "Pod", Namespace: namespace, Name: p.Name, Detail: podStatusDetail(&p)})
			}
			return Result{
				Verdict:      VerdictBlocked,
				FailedStep:   StepService,
				Reason:       fmt.Sprintf("%d pod(s) match Service %s/%s but none are Ready.", len(live), namespace, name),
				Evidence:     evidence,
				SuggestedFix: "Fix the pods' readiness first; a Service only routes to Ready pods.",
			}, nil
		}

		for _, sp := range ports {
			if sp.TargetPort.Type == intstr.String {
				portName := sp.TargetPort.StrVal
				if !anyPodHasNamedPort(ready, portName) {
					return Result{
						Verdict:      VerdictBlocked,
						FailedStep:   StepService,
						Reason:       fmt.Sprintf("Service port %d uses targetPort %q, but no ready pod has a container port with that name.", sp.Port, portName),
						Evidence:     []Evidence{svcRef},
						SuggestedFix: fmt.Sprintf("Name a container port %q in the pod spec, or set targetPort to the port number.", portName),
					}, nil
				}
				continue
			}
			target := sp.TargetPort.IntValue()
			if target == 0 {
				target = int(sp.Port)
			}
			if !anyPodDeclaresPort(ready, target) {
				warnings = append(warnings, fmt.Sprintf(
					"Service port %d targets container port %d, which no ready pod declares. Declaring ports is optional, so confirm the application listens on %d.",
					sp.Port, target, target))
			}
		}
	}

	sliceList, err := cs.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + name,
	})
	if err != nil {
		return Result{}, fmt.Errorf("list endpointslices for service %s/%s: %w", namespace, name, err)
	}
	readyEndpoints := 0
	for _, s := range sliceList.Items {
		for _, ep := range s.Endpoints {
			// A nil Ready condition means "unknown" and is treated as ready,
			// which is how the EndpointSlice API tells consumers to read it.
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				readyEndpoints++
			}
		}
	}
	if readyEndpoints == 0 {
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepService,
			Reason:       fmt.Sprintf("Service %s/%s has no ready endpoints in its EndpointSlices.", namespace, name),
			Evidence:     []Evidence{svcRef},
			Warnings:     warnings,
			SuggestedFix: fmt.Sprintf("Inspect the slices: kubectl get endpointslices -n %s -l %s=%s", namespace, discoveryv1.LabelServiceName, name),
		}, nil
	}

	return Result{
		Verdict:  VerdictOK,
		Reason:   fmt.Sprintf("Service %s/%s has %d ready endpoint(s).", namespace, name, readyEndpoints),
		Evidence: []Evidence{svcRef},
		Warnings: warnings,
	}, nil
}

func isPodReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// podStatusDetail gives the most useful one-line reason a pod is not ready.
func podStatusDetail(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return fmt.Sprintf("phase %s, container %s waiting: %s", p.Status.Phase, cs.Name, cs.State.Waiting.Reason)
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Reason != "" {
			return fmt.Sprintf("phase %s, not ready: %s", p.Status.Phase, c.Reason)
		}
	}
	return fmt.Sprintf("phase %s, not ready", p.Status.Phase)
}

func anyPodHasNamedPort(pods []corev1.Pod, name string) bool {
	for _, p := range pods {
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == name {
					return true
				}
			}
		}
	}
	return false
}

func anyPodDeclaresPort(pods []corev1.Pod, port int) bool {
	for _, p := range pods {
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if int(cp.ContainerPort) == port {
					return true
				}
			}
		}
	}
	return false
}

func describePorts(ports []corev1.ServicePort) string {
	if len(ports) == 0 {
		return "none"
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = corev1.ProtocolTCP
		}
		out = append(out, fmt.Sprintf("%d/%s", p.Port, proto))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

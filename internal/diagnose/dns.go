package diagnose

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

const (
	dnsNamespace   = "kube-system"
	dnsServiceName = "kube-dns"
	dnsPort        = 53
)

// CheckDNS checks the API-visible health of the cluster DNS service.
//
// It verifies the kube-dns Service, its UDP and TCP DNS ports, selected
// backend pod readiness, and ready EndpointSlice endpoints. It does not send
// DNS queries, so an OK verdict does not prove that a particular name resolves.
func CheckDNS(ctx context.Context, cs kubernetes.Interface) (Result, error) {
	svc, err := cs.CoreV1().Services(dnsNamespace).Get(ctx, dnsServiceName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepDNS,
			Reason:       "Cluster DNS Service kube-system/kube-dns does not exist.",
			SuggestedFix: "Restore the cluster DNS Service and verify the cluster DNS addon.",
		}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("get cluster DNS service %s/%s: %w", dnsNamespace, dnsServiceName, err)
	}

	serviceEvidence := Evidence{
		Kind:      "Service",
		Namespace: dnsNamespace,
		Name:      dnsServiceName,
		Detail:    fmt.Sprintf("clusterIP: %s; ports: %s", svc.Spec.ClusterIP, describePorts(svc.Spec.Ports)),
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepDNS,
			Reason:       "Cluster DNS Service kube-system/kube-dns has no ClusterIP.",
			Evidence:     []Evidence{serviceEvidence},
			SuggestedFix: "Configure kube-dns as a ClusterIP Service so pods can use it as their DNS server.",
		}, nil
	}

	hasUDP, hasTCP := false, false
	for _, port := range svc.Spec.Ports {
		if int(port.Port) != dnsPort {
			continue
		}
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		switch protocol {
		case corev1.ProtocolUDP:
			hasUDP = true
		case corev1.ProtocolTCP:
			hasTCP = true
		}
	}
	if !hasUDP || !hasTCP {
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepDNS,
			Reason:       "Cluster DNS Service kube-system/kube-dns must expose port 53 over both UDP and TCP.",
			Evidence:     []Evidence{serviceEvidence},
			SuggestedFix: "Restore the standard UDP and TCP port 53 entries on the kube-dns Service.",
		}, nil
	}

	var warnings []string
	var readyPods []corev1.Pod
	if len(svc.Spec.Selector) == 0 {
		warnings = append(warnings, "Cluster DNS Service has no selector; its backend pods are managed manually or by another controller.")
	} else {
		selector := labels.SelectorFromSet(svc.Spec.Selector).String()
		podList, err := cs.CoreV1().Pods(dnsNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return Result{}, fmt.Errorf("list pods for cluster DNS service %s/%s: %w", dnsNamespace, dnsServiceName, err)
		}

		var livePods []corev1.Pod
		for _, pod := range podList.Items {
			if pod.DeletionTimestamp != nil {
				continue
			}
			livePods = append(livePods, pod)
			if isPodReady(&pod) {
				readyPods = append(readyPods, pod)
			}
		}

		if len(livePods) == 0 {
			serviceEvidence.Detail += "; selector: " + selector
			return Result{
				Verdict:      VerdictBlocked,
				FailedStep:   StepDNS,
				Reason:       "The selector of cluster DNS Service kube-system/kube-dns matches no pods.",
				Evidence:     []Evidence{serviceEvidence},
				SuggestedFix: fmt.Sprintf("Check the CoreDNS pods and Service selector: kubectl get pods -n %s -l %s", dnsNamespace, selector),
			}, nil
		}
		if len(readyPods) == 0 {
			evidence := []Evidence{serviceEvidence}
			for i := range livePods {
				if len(evidence) >= maxEvidence {
					break
				}
				pod := &livePods[i]
				evidence = append(evidence, Evidence{
					Kind:      "Pod",
					Namespace: dnsNamespace,
					Name:      pod.Name,
					Detail:    podStatusDetail(pod),
				})
			}
			return Result{
				Verdict:      VerdictBlocked,
				FailedStep:   StepDNS,
				Reason:       fmt.Sprintf("Cluster DNS Service kube-system/kube-dns selects %d pod(s), but none are Ready.", len(livePods)),
				Evidence:     evidence,
				SuggestedFix: "Restore the CoreDNS pods to Ready and inspect their logs for startup or configuration errors.",
			}, nil
		}
	}

	sliceList, err := cs.DiscoveryV1().EndpointSlices(dnsNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + dnsServiceName,
	})
	if err != nil {
		return Result{}, fmt.Errorf("list EndpointSlices for cluster DNS service %s/%s: %w", dnsNamespace, dnsServiceName, err)
	}

	readyEndpoints := 0
	for _, slice := range sliceList.Items {
		for _, endpoint := range slice.Endpoints {
			// A nil Ready condition means "unknown" and is treated as ready.
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				readyEndpoints++
			}
		}
	}
	if readyEndpoints == 0 {
		evidence := []Evidence{serviceEvidence}
		for _, slice := range sliceList.Items {
			if len(evidence) >= maxEvidence {
				break
			}
			evidence = append(evidence, Evidence{
				Kind:      "EndpointSlice",
				Namespace: dnsNamespace,
				Name:      slice.Name,
				Detail:    "no ready endpoints",
			})
		}
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepDNS,
			Reason:       "Cluster DNS Service kube-system/kube-dns has no ready EndpointSlice endpoints.",
			Evidence:     evidence,
			Warnings:     warnings,
			SuggestedFix: "Inspect CoreDNS endpoint slices: kubectl get endpointslices -n kube-system -l kubernetes.io/service-name=kube-dns",
		}, nil
	}

	evidence := []Evidence{serviceEvidence}
	for i := range readyPods {
		if len(evidence) >= maxEvidence {
			break
		}
		evidence = append(evidence, Evidence{
			Kind:      "Pod",
			Namespace: dnsNamespace,
			Name:      readyPods[i].Name,
			Detail:    "Ready",
		})
	}
	for _, slice := range sliceList.Items {
		if len(evidence) >= maxEvidence {
			break
		}
		sliceReady := 0
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				sliceReady++
			}
		}
		if sliceReady > 0 {
			evidence = append(evidence, Evidence{
				Kind:      "EndpointSlice",
				Namespace: dnsNamespace,
				Name:      slice.Name,
				Detail:    fmt.Sprintf("%d ready endpoint(s)", sliceReady),
			})
		}
	}

	reason := fmt.Sprintf("Cluster DNS Service kube-system/kube-dns has %d ready endpoint(s).", readyEndpoints)
	if len(svc.Spec.Selector) > 0 {
		reason = fmt.Sprintf("Cluster DNS Service kube-system/kube-dns has %d Ready pod(s) and %d ready endpoint(s).", len(readyPods), readyEndpoints)
	}
	return Result{
		Verdict:  VerdictOK,
		Reason:   reason,
		Evidence: evidence,
		Warnings: warnings,
	}, nil
}

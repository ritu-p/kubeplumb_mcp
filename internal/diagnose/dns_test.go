package diagnose

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func dnsTestService(selector map[string]string, ports ...corev1.ServicePort) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: dnsNamespace, Name: dnsServiceName},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Selector:  selector,
			Ports:     ports,
		},
	}
}

func dnsTestPorts() []corev1.ServicePort {
	return []corev1.ServicePort{
		{Name: "dns", Port: dnsPort, Protocol: corev1.ProtocolUDP},
		{Name: "dns-tcp", Port: dnsPort, Protocol: corev1.ProtocolTCP},
	}
}

func dnsTestPod(name string, ready bool) *corev1.Pod {
	condition := corev1.ConditionFalse
	if ready {
		condition = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dnsNamespace,
			Name:      name,
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: condition}},
		},
	}
}

func dnsTestEndpointSlice(ready bool) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dnsNamespace,
			Name:      "kube-dns-test",
			Labels:    map[string]string{discoveryv1.LabelServiceName: dnsServiceName},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.10"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}
}

func TestCheckDNS(t *testing.T) {
	selector := map[string]string{"k8s-app": "kube-dns"}
	service := dnsTestService(selector, dnsTestPorts()...)

	tests := []struct {
		name        string
		objects     []runtime.Object
		wantVerdict string
		wantReason  string
		wantWarning bool
	}{
		{
			name:        "DNS service missing",
			wantVerdict: VerdictBlocked,
			wantReason:  "does not exist",
		},
		{
			name: "TCP port missing",
			objects: []runtime.Object{
				dnsTestService(selector, corev1.ServicePort{Port: dnsPort, Protocol: corev1.ProtocolUDP}),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "both UDP and TCP",
		},
		{
			name:        "selector matches no pods",
			objects:     []runtime.Object{service},
			wantVerdict: VerdictBlocked,
			wantReason:  "matches no pods",
		},
		{
			name: "pods not ready",
			objects: []runtime.Object{
				service,
				dnsTestPod("coredns-1", false),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "none are Ready",
		},
		{
			name: "no ready endpoints",
			objects: []runtime.Object{
				service,
				dnsTestPod("coredns-1", true),
				dnsTestEndpointSlice(false),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "no ready EndpointSlice endpoints",
		},
		{
			name: "healthy DNS service",
			objects: []runtime.Object{
				service,
				dnsTestPod("coredns-1", true),
				dnsTestEndpointSlice(true),
			},
			wantVerdict: VerdictOK,
			wantReason:  "1 Ready pod(s) and 1 ready endpoint(s)",
		},
		{
			name: "selectorless DNS service with endpoints",
			objects: []runtime.Object{
				dnsTestService(nil, dnsTestPorts()...),
				dnsTestEndpointSlice(true),
			},
			wantVerdict: VerdictOK,
			wantReason:  "1 ready endpoint(s)",
			wantWarning: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objects...)
			got, err := CheckDNS(context.Background(), cs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
			if got.Verdict == VerdictBlocked && got.FailedStep != StepDNS {
				t.Errorf("failed_step = %q, want %q", got.FailedStep, StepDNS)
			}
			if (len(got.Warnings) > 0) != tc.wantWarning {
				t.Errorf("warnings = %v, wantWarning = %v", got.Warnings, tc.wantWarning)
			}
		})
	}
}

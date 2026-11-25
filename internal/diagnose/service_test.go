package diagnose

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

const ns = "shop"

func service(selector map[string]string, targetPort intstr.IntOrString) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web"},
		Spec: corev1.ServiceSpec{
			Selector: selector,
			Ports:    []corev1.ServicePort{{Port: 80, TargetPort: targetPort}},
		},
	}
}

func pod(name string, lbls map[string]string, ready bool, portName string) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "app",
			Ports: []corev1.ContainerPort{{Name: portName, ContainerPort: 8080}},
		}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

func slice(ready bool) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "web-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "web"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.5"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}
}

func TestCheckService(t *testing.T) {
	app := map[string]string{"app": "web"}

	tests := []struct {
		name        string
		objects     []runtime.Object
		port        int
		wantVerdict string
		wantReason  string // substring
		wantWarning bool
	}{
		{
			name:        "service missing",
			wantVerdict: VerdictBlocked,
			wantReason:  "does not exist",
		},
		{
			name:        "port not exposed",
			objects:     []runtime.Object{service(app, intstr.FromInt32(8080)), pod("web-1", app, true, "http"), slice(true)},
			port:        443,
			wantVerdict: VerdictBlocked,
			wantReason:  "does not expose port 443",
		},
		{
			name:        "selector matches no pods",
			objects:     []runtime.Object{service(map[string]string{"app": "wbe"}, intstr.FromInt32(8080)), pod("web-1", app, true, "http")},
			wantVerdict: VerdictBlocked,
			wantReason:  "matches no pods",
		},
		{
			name:        "pods not ready",
			objects:     []runtime.Object{service(app, intstr.FromInt32(8080)), pod("web-1", app, false, "http"), slice(false)},
			wantVerdict: VerdictBlocked,
			wantReason:  "none are Ready",
		},
		{
			name:        "named targetPort does not resolve",
			objects:     []runtime.Object{service(app, intstr.FromString("metrics")), pod("web-1", app, true, "http"), slice(true)},
			wantVerdict: VerdictBlocked,
			wantReason:  `targetPort "metrics"`,
		},
		{
			name:        "no ready endpoints",
			objects:     []runtime.Object{service(app, intstr.FromInt32(8080)), pod("web-1", app, true, "http")},
			wantVerdict: VerdictBlocked,
			wantReason:  "no ready endpoints",
		},
		{
			name:        "undeclared numeric targetPort only warns",
			objects:     []runtime.Object{service(app, intstr.FromInt32(9090)), pod("web-1", app, true, "http"), slice(true)},
			wantVerdict: VerdictOK,
			wantReason:  "1 ready endpoint",
			wantWarning: true,
		},
		{
			name:        "healthy",
			objects:     []runtime.Object{service(app, intstr.FromString("http")), pod("web-1", app, true, "http"), slice(true)},
			port:        80,
			wantVerdict: VerdictOK,
			wantReason:  "1 ready endpoint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objects...)
			got, err := CheckService(context.Background(), cs, ns, "web", tc.port)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
			if got.Verdict == VerdictBlocked && got.FailedStep != StepService {
				t.Errorf("failed_step = %q, want %q", got.FailedStep, StepService)
			}
			if (len(got.Warnings) > 0) != tc.wantWarning {
				t.Errorf("warnings = %v, wantWarning = %v", got.Warnings, tc.wantWarning)
			}
		})
	}
}

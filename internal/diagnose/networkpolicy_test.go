package diagnose

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func networkPolicyTestBaseObjects() []runtime.Object {
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "clients", Labels: map[string]string{"team": "client"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "servers", Labels: map[string]string{"team": "server"}}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "clients",
				Name:      "frontend",
				Labels:    map[string]string{"app": "frontend"},
			},
			Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "frontend"}}},
			Status: corev1.PodStatus{PodIP: "10.1.0.10"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "servers",
				Name:      "web",
				Labels:    map[string]string{"app": "web"},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  "web",
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
			}}},
			Status: corev1.PodStatus{PodIP: "10.2.0.20"},
		},
	}
}

func networkPolicyTestPolicy(
	name, namespace string,
	selectedLabels map[string]string,
	types []networkingv1.PolicyType,
	ingress []networkingv1.NetworkPolicyIngressRule,
	egress []networkingv1.NetworkPolicyEgressRule,
) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectedLabels},
			PolicyTypes: types,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func networkPolicyTestPort(port int32, protocol corev1.Protocol) networkingv1.NetworkPolicyPort {
	value := intstr.FromInt32(port)
	return networkingv1.NetworkPolicyPort{Port: &value, Protocol: &protocol}
}

func networkPolicyTestPeer(podLabels, namespaceLabels map[string]string) networkingv1.NetworkPolicyPeer {
	peer := networkingv1.NetworkPolicyPeer{}
	if podLabels != nil {
		peer.PodSelector = &metav1.LabelSelector{MatchLabels: podLabels}
	}
	if namespaceLabels != nil {
		peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: namespaceLabels}
	}
	return peer
}

func TestEvaluateNetworkPolicies(t *testing.T) {
	tests := []struct {
		name        string
		policies    []*networkingv1.NetworkPolicy
		flow        NetworkPolicyFlow
		noDestIP    bool
		wantVerdict string
		wantReason  string
	}{
		{
			name:        "no policies allow both directions",
			wantVerdict: VerdictOK,
			wantReason:  "allowed by default (not isolated)",
		},
		{
			name: "egress isolation denies without an allow rule",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("deny-egress", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "egress is denied",
		},
		{
			name: "ingress isolation denies a nonmatching peer",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("deny-ingress", "servers", map[string]string{"app": "web"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					[]networkingv1.NetworkPolicyIngressRule{{
						From:  []networkingv1.NetworkPolicyPeer{networkPolicyTestPeer(map[string]string{"app": "other"}, nil)},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8080, corev1.ProtocolTCP)},
					}}, nil),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "ingress is denied",
		},
		{
			name: "ingress allows a matching namespace pod and port",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("allow-ingress", "servers", map[string]string{"app": "web"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					[]networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{
							networkPolicyTestPeer(map[string]string{"app": "frontend"}, map[string]string{"team": "client"}),
						},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8080, corev1.ProtocolTCP)},
					}}, nil),
			},
			wantVerdict: VerdictOK,
			wantReason:  "ingress: allowed by a matching policy",
		},
		{
			name: "egress allows a matching namespace pod and port",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("allow-egress", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{
							networkPolicyTestPeer(map[string]string{"app": "web"}, map[string]string{"team": "server"}),
						},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8080, corev1.ProtocolTCP)},
					}}),
			},
			wantVerdict: VerdictOK,
			wantReason:  "egress: allowed by a matching policy",
		},
		{
			name: "policies are additive",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("allow-other-port", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To:    []networkingv1.NetworkPolicyPeer{networkPolicyTestPeer(map[string]string{"app": "web"}, map[string]string{"team": "server"})},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8081, corev1.ProtocolTCP)},
					}}),
				networkPolicyTestPolicy("allow-web", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To:    []networkingv1.NetworkPolicyPeer{networkPolicyTestPeer(map[string]string{"app": "web"}, map[string]string{"team": "server"})},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8080, corev1.ProtocolTCP)},
					}}),
			},
			wantVerdict: VerdictOK,
			wantReason:  "egress: allowed by a matching policy",
		},
		{
			name: "named destination port matches",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("allow-http", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{networkPolicyTestPeer(map[string]string{"app": "web"}, map[string]string{"team": "server"})},
						Ports: []networkingv1.NetworkPolicyPort{{
							Port:     ptrIntOrString(intstr.FromString("http")),
							Protocol: protocolPointer(corev1.ProtocolTCP),
						}},
					}}),
			},
			wantVerdict: VerdictOK,
			wantReason:  "egress: allowed by a matching policy",
		},
		{
			name: "protocol mismatch denies traffic",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("allow-tcp-only", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To:    []networkingv1.NetworkPolicyPeer{networkPolicyTestPeer(map[string]string{"app": "web"}, map[string]string{"team": "server"})},
						Ports: []networkingv1.NetworkPolicyPort{networkPolicyTestPort(8080, corev1.ProtocolTCP)},
					}}),
			},
			flow: NetworkPolicyFlow{
				SourceNamespace: "clients", SourcePod: "frontend",
				DestinationNamespace: "servers", DestinationPod: "web",
				Port: 8080, Protocol: corev1.ProtocolUDP,
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "egress is denied",
		},
		{
			name: "empty policy types default to ingress only",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("ingress-only", "clients", map[string]string{"app": "frontend"},
					nil, nil, nil),
			},
			wantVerdict: VerdictOK,
			wantReason:  "egress: allowed by default (not isolated)",
		},
		{
			name: "ipBlock except denies matching destination IP",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("ipblock", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{{
							IPBlock: &networkingv1.IPBlock{
								CIDR:   "10.2.0.0/24",
								Except: []string{"10.2.0.0/25"},
							},
						}},
					}}),
			},
			wantVerdict: VerdictBlocked,
			wantReason:  "egress is denied",
		},
		{
			name: "ipBlock allows destination IP",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("ipblock-allow", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{{
							IPBlock: &networkingv1.IPBlock{CIDR: "10.2.0.0/24"},
						}},
					}}),
			},
			wantVerdict: VerdictOK,
			wantReason:  "egress: allowed by a matching policy",
		},
		{
			name: "ipBlock without destination IP is inconclusive",
			policies: []*networkingv1.NetworkPolicy{
				networkPolicyTestPolicy("ipblock-unknown", "clients", map[string]string{"app": "frontend"},
					[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{{
							IPBlock: &networkingv1.IPBlock{CIDR: "10.2.0.0/24"},
						}},
					}}),
			},
			noDestIP:    true,
			wantVerdict: VerdictInconclusive,
			wantReason:  "has no valid Pod IP",
		},
		{
			name: "missing pod is inconclusive",
			flow: NetworkPolicyFlow{
				SourceNamespace: "clients", SourcePod: "missing",
				DestinationNamespace: "servers", DestinationPod: "web",
				Port: 8080, Protocol: corev1.ProtocolTCP,
			},
			wantVerdict: VerdictInconclusive,
			wantReason:  "Source Pod clients/missing does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objects := networkPolicyTestBaseObjects()
			for _, policy := range tc.policies {
				objects = append(objects, policy)
			}
			if tc.noDestIP {
				for _, object := range objects {
					if pod, ok := object.(*corev1.Pod); ok && pod.Name == "web" {
						pod.Status.PodIP = ""
					}
				}
			}
			cs := fake.NewSimpleClientset(objects...)
			flow := tc.flow
			if flow.SourceNamespace == "" {
				flow = NetworkPolicyFlow{
					SourceNamespace:      "clients",
					SourcePod:            "frontend",
					DestinationNamespace: "servers",
					DestinationPod:       "web",
					Port:                 8080,
					Protocol:             corev1.ProtocolTCP,
				}
			}

			got, err := EvaluateNetworkPolicies(context.Background(), cs, flow)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
			if got.Verdict == VerdictBlocked && got.FailedStep != StepNetworkPolicy {
				t.Errorf("failed_step = %q, want %q", got.FailedStep, StepNetworkPolicy)
			}
		})
	}
}

func ptrIntOrString(value intstr.IntOrString) *intstr.IntOrString {
	return &value
}

func protocolPointer(value corev1.Protocol) *corev1.Protocol {
	return &value
}

package diagnose

import (
	"context"
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyFlow identifies one pod-to-pod connection to evaluate.
type NetworkPolicyFlow struct {
	SourceNamespace      string
	SourcePod            string
	DestinationNamespace string
	DestinationPod       string
	Port                 int
	Protocol             corev1.Protocol
}

type policyDirectionEvaluation struct {
	isolated      bool
	allowed       bool
	uncertain     bool
	unknownReason []string
	selected      []networkingv1.NetworkPolicy
	allowing      map[string]bool
}

// EvaluateNetworkPolicies evaluates standard Kubernetes NetworkPolicy rules
// for a pod-to-pod flow. It does not evaluate CNI-specific policy resources or
// policies applied outside the Kubernetes NetworkPolicy API.
func EvaluateNetworkPolicies(ctx context.Context, cs kubernetes.Interface, flow NetworkPolicyFlow) (Result, error) {
	if flow.SourceNamespace == "" || flow.SourcePod == "" ||
		flow.DestinationNamespace == "" || flow.DestinationPod == "" {
		return Result{}, fmt.Errorf("source and destination namespaces and pod names are required")
	}
	if flow.Port < 1 || flow.Port > 65535 {
		return Result{}, fmt.Errorf("destination port must be between 1 and 65535")
	}
	if flow.Protocol == "" {
		flow.Protocol = corev1.ProtocolTCP
	}
	if flow.Protocol != corev1.ProtocolTCP &&
		flow.Protocol != corev1.ProtocolUDP &&
		flow.Protocol != corev1.ProtocolSCTP {
		return Result{}, fmt.Errorf("protocol must be TCP, UDP, or SCTP")
	}

	sourcePod, err := cs.CoreV1().Pods(flow.SourceNamespace).Get(ctx, flow.SourcePod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return networkPolicyInconclusive(
			fmt.Sprintf("Source Pod %s/%s does not exist.", flow.SourceNamespace, flow.SourcePod),
			"Verify the source namespace and pod name, then retry.",
		)
	}
	if err != nil {
		return Result{}, fmt.Errorf("get source pod %s/%s: %w", flow.SourceNamespace, flow.SourcePod, err)
	}
	destinationPod, err := cs.CoreV1().Pods(flow.DestinationNamespace).Get(ctx, flow.DestinationPod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return networkPolicyInconclusive(
			fmt.Sprintf("Destination Pod %s/%s does not exist.", flow.DestinationNamespace, flow.DestinationPod),
			"Verify the destination namespace and pod name, then retry.",
		)
	}
	if err != nil {
		return Result{}, fmt.Errorf("get destination pod %s/%s: %w", flow.DestinationNamespace, flow.DestinationPod, err)
	}

	if sourcePod.Spec.HostNetwork || destinationPod.Spec.HostNetwork {
		return networkPolicyInconclusive(
			"At least one pod uses host networking, whose NetworkPolicy behavior is implementation-dependent.",
			"Evaluate the host-network traffic using the cluster CNI's documentation and policy tools.",
		)
	}

	sourceNamespace, err := cs.CoreV1().Namespaces().Get(ctx, flow.SourceNamespace, metav1.GetOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("get source namespace %q: %w", flow.SourceNamespace, err)
	}
	destinationNamespace := sourceNamespace
	if flow.DestinationNamespace != flow.SourceNamespace {
		destinationNamespace, err = cs.CoreV1().Namespaces().Get(ctx, flow.DestinationNamespace, metav1.GetOptions{})
		if err != nil {
			return Result{}, fmt.Errorf("get destination namespace %q: %w", flow.DestinationNamespace, err)
		}
	}

	sourcePolicies, err := cs.NetworkingV1().NetworkPolicies(flow.SourceNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list NetworkPolicies in source namespace %q: %w", flow.SourceNamespace, err)
	}
	destinationPolicies := sourcePolicies
	if flow.DestinationNamespace != flow.SourceNamespace {
		destinationPolicies, err = cs.NetworkingV1().NetworkPolicies(flow.DestinationNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return Result{}, fmt.Errorf("list NetworkPolicies in destination namespace %q: %w", flow.DestinationNamespace, err)
		}
	}

	egress, err := evaluatePolicyDirection(
		sourcePolicies.Items, networkingv1.PolicyTypeEgress, *sourcePod,
		*destinationPod, destinationNamespace, *destinationPod, flow.Port, flow.Protocol,
	)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate source egress policies: %w", err)
	}
	ingress, err := evaluatePolicyDirection(
		destinationPolicies.Items, networkingv1.PolicyTypeIngress, *destinationPod,
		*sourcePod, sourceNamespace, *destinationPod, flow.Port, flow.Protocol,
	)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate destination ingress policies: %w", err)
	}

	evidence := []Evidence{
		{Kind: "Pod", Namespace: flow.SourceNamespace, Name: flow.SourcePod, Detail: "source"},
		{Kind: "Pod", Namespace: flow.DestinationNamespace, Name: flow.DestinationPod, Detail: "destination"},
	}
	evidence = appendDirectionEvidence(evidence, egress, "egress", "source")
	evidence = appendDirectionEvidence(evidence, ingress, "ingress", "destination")

	warnings := []string{
		"Only standard Kubernetes NetworkPolicy resources are evaluated; CNI-specific policy layers and actual packet delivery are not verified.",
	}
	egressStatus := policyDirectionStatus(egress)
	ingressStatus := policyDirectionStatus(ingress)
	baseReason := fmt.Sprintf(
		"Traffic from %s/%s to %s/%s on %s port %d",
		flow.SourceNamespace, flow.SourcePod, flow.DestinationNamespace, flow.DestinationPod, flow.Protocol, flow.Port,
	)

	var blocked []string
	var uncertain []string
	if egressStatus == "denied" {
		blocked = append(blocked, "egress")
	}
	if ingressStatus == "denied" {
		blocked = append(blocked, "ingress")
	}
	if egressStatus == "inconclusive" {
		uncertain = append(uncertain, egress.unknownReason...)
	}
	if ingressStatus == "inconclusive" {
		uncertain = append(uncertain, ingress.unknownReason...)
	}

	if len(blocked) > 0 {
		verb := "are"
		if len(blocked) == 1 {
			verb = "is"
		}
		status := fmt.Sprintf("%s is blocked by NetworkPolicy: %s %s denied", baseReason, strings.Join(blocked, " and "), verb)
		if len(blocked) == 1 {
			otherStatus := ingressStatus
			if blocked[0] == "ingress" {
				otherStatus = egressStatus
			}
			otherDirection := "egress"
			if blocked[0] == "egress" {
				otherDirection = "ingress"
			}
			status += fmt.Sprintf("; %s is %s", otherDirection, otherStatus)
		}
		return Result{
			Verdict:      VerdictBlocked,
			FailedStep:   StepNetworkPolicy,
			Reason:       status + ".",
			Evidence:     evidence,
			Warnings:     warnings,
			SuggestedFix: suggestedPolicyFix(egressStatus, ingressStatus),
		}, nil
	}
	if len(uncertain) > 0 {
		return Result{
			Verdict:      VerdictInconclusive,
			Reason:       fmt.Sprintf("%s cannot be fully evaluated: %s.", baseReason, strings.Join(uniqueStrings(uncertain), "; ")),
			Evidence:     evidence,
			Warnings:     warnings,
			SuggestedFix: "Retry when both pods have assigned Pod IPs, or inspect the relevant NetworkPolicy and CNI behavior.",
		}, nil
	}

	return Result{
		Verdict:  VerdictOK,
		Reason:   fmt.Sprintf("%s is allowed by standard Kubernetes NetworkPolicy rules (egress: %s; ingress: %s).", baseReason, egressStatus, ingressStatus),
		Evidence: evidence,
		Warnings: warnings,
	}, nil
}

func networkPolicyInconclusive(reason, suggestedFix string) (Result, error) {
	return Result{
		Verdict:      VerdictInconclusive,
		Reason:       reason,
		SuggestedFix: suggestedFix,
	}, nil
}

func evaluatePolicyDirection(
	policies []networkingv1.NetworkPolicy,
	direction networkingv1.PolicyType,
	selectedPod corev1.Pod,
	peerPod corev1.Pod,
	peerNamespace *corev1.Namespace,
	destinationPod corev1.Pod,
	port int,
	protocol corev1.Protocol,
) (policyDirectionEvaluation, error) {
	result := policyDirectionEvaluation{allowing: make(map[string]bool)}
	for i := range policies {
		policy := &policies[i]
		if !policyAppliesToDirection(policy, direction) {
			continue
		}
		selected, err := labelSelectorMatches(&policy.Spec.PodSelector, selectedPod.Labels)
		if err != nil {
			return result, fmt.Errorf("invalid podSelector in NetworkPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
		}
		if !selected {
			continue
		}

		result.isolated = true
		result.selected = append(result.selected, *policy)
		rulesAllow := false
		for _, rule := range policyRules(policy, direction) {
			matches, unknown, err := networkPolicyRuleMatches(
				rule.peers, rule.ports, policy.Namespace, peerPod, peerNamespace,
				destinationPod, port, protocol,
			)
			if err != nil {
				return result, fmt.Errorf("evaluate NetworkPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
			}
			if matches {
				rulesAllow = true
				break
			}
			result.unknownReason = append(result.unknownReason, unknown...)
		}
		if rulesAllow {
			result.allowing[policy.Name] = true
		}
	}

	if !result.isolated || len(result.allowing) > 0 {
		result.allowed = true
		result.unknownReason = nil
	} else if len(result.unknownReason) > 0 {
		result.uncertain = true
	}
	return result, nil
}

type networkPolicyRule struct {
	peers []networkingv1.NetworkPolicyPeer
	ports []networkingv1.NetworkPolicyPort
}

func policyRules(policy *networkingv1.NetworkPolicy, direction networkingv1.PolicyType) []networkPolicyRule {
	var rules []networkPolicyRule
	if direction == networkingv1.PolicyTypeIngress {
		for _, rule := range policy.Spec.Ingress {
			rules = append(rules, networkPolicyRule{peers: rule.From, ports: rule.Ports})
		}
		return rules
	}
	for _, rule := range policy.Spec.Egress {
		rules = append(rules, networkPolicyRule{peers: rule.To, ports: rule.Ports})
	}
	return rules
}

func policyAppliesToDirection(policy *networkingv1.NetworkPolicy, direction networkingv1.PolicyType) bool {
	if len(policy.Spec.PolicyTypes) == 0 {
		return direction == networkingv1.PolicyTypeIngress ||
			(direction == networkingv1.PolicyTypeEgress && len(policy.Spec.Egress) > 0)
	}
	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == direction {
			return true
		}
	}
	return false
}

func networkPolicyRuleMatches(
	peers []networkingv1.NetworkPolicyPeer,
	ports []networkingv1.NetworkPolicyPort,
	policyNamespace string,
	peerPod corev1.Pod,
	peerNamespace *corev1.Namespace,
	destinationPod corev1.Pod,
	destinationPort int,
	protocol corev1.Protocol,
) (bool, []string, error) {
	if !networkPolicyPortsMatch(ports, destinationPod, destinationPort, protocol) {
		return false, nil, nil
	}

	peerAllowed := len(peers) == 0
	var unknown []string
	for _, peer := range peers {
		matches, uncertainty, err := networkPolicyPeerMatches(peer, policyNamespace, peerPod, peerNamespace)
		if err != nil {
			return false, nil, err
		}
		if matches {
			peerAllowed = true
			break
		}
		if uncertainty != "" {
			unknown = append(unknown, uncertainty)
		}
	}
	return peerAllowed, unknown, nil
}

func networkPolicyPeerMatches(
	peer networkingv1.NetworkPolicyPeer,
	policyNamespace string,
	pod corev1.Pod,
	namespace *corev1.Namespace,
) (bool, string, error) {
	if peer.IPBlock != nil {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			return false, "", fmt.Errorf("IPBlock cannot be combined with podSelector or namespaceSelector")
		}
		ip := net.ParseIP(pod.Status.PodIP)
		if ip == nil {
			return false, fmt.Sprintf("cannot compare ipBlock %s because Pod %s/%s has no valid Pod IP", peer.IPBlock.CIDR, pod.Namespace, pod.Name), nil
		}
		_, cidr, err := net.ParseCIDR(peer.IPBlock.CIDR)
		if err != nil {
			return false, "", fmt.Errorf("invalid ipBlock CIDR %q: %w", peer.IPBlock.CIDR, err)
		}
		if !cidr.Contains(ip) {
			return false, "", nil
		}
		for _, exceptCIDR := range peer.IPBlock.Except {
			_, except, err := net.ParseCIDR(exceptCIDR)
			if err != nil {
				return false, "", fmt.Errorf("invalid ipBlock except CIDR %q: %w", exceptCIDR, err)
			}
			if except.Contains(ip) {
				return false, "", nil
			}
		}
		return true, "", nil
	}

	if peer.PodSelector == nil && peer.NamespaceSelector == nil {
		return false, "", nil
	}
	if peer.NamespaceSelector != nil {
		matches, err := labelSelectorMatches(peer.NamespaceSelector, namespace.Labels)
		if err != nil || !matches {
			return matches, "", err
		}
	} else if pod.Namespace != policyNamespace {
		return false, "", nil
	}
	if peer.PodSelector != nil {
		matches, err := labelSelectorMatches(peer.PodSelector, pod.Labels)
		return matches, "", err
	}
	return true, "", nil
}

func networkPolicyPortsMatch(
	ports []networkingv1.NetworkPolicyPort,
	destinationPod corev1.Pod,
	destinationPort int,
	protocol corev1.Protocol,
) bool {
	if len(ports) == 0 {
		return true
	}
	for _, policyPort := range ports {
		policyProtocol := corev1.ProtocolTCP
		if policyPort.Protocol != nil {
			policyProtocol = *policyPort.Protocol
		}
		if policyProtocol != protocol {
			continue
		}
		if policyPort.Port == nil {
			return true
		}
		switch policyPort.Port.Type {
		case intstr.Int:
			start := int(policyPort.Port.IntVal)
			end := start
			if policyPort.EndPort != nil {
				end = int(*policyPort.EndPort)
			}
			if destinationPort >= start && destinationPort <= end {
				return true
			}
		case intstr.String:
			if policyPort.EndPort != nil {
				continue
			}
			for _, container := range destinationPod.Spec.Containers {
				for _, containerPort := range container.Ports {
					containerProtocol := containerPort.Protocol
					if containerProtocol == "" {
						containerProtocol = corev1.ProtocolTCP
					}
					if containerPort.Name == policyPort.Port.StrVal &&
						int(containerPort.ContainerPort) == destinationPort &&
						containerProtocol == protocol {
						return true
					}
				}
			}
		}
	}
	return false
}

func labelSelectorMatches(selector *metav1.LabelSelector, objectLabels map[string]string) (bool, error) {
	parsed, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}
	return parsed.Matches(labels.Set(objectLabels)), nil
}

func policyDirectionStatus(result policyDirectionEvaluation) string {
	if result.allowed {
		if result.isolated {
			return "allowed by a matching policy"
		}
		return "allowed by default (not isolated)"
	}
	if result.uncertain {
		return "inconclusive"
	}
	return "denied"
}

func appendDirectionEvidence(evidence []Evidence, result policyDirectionEvaluation, direction, selectedRole string) []Evidence {
	for _, policy := range result.selected {
		if len(evidence) >= maxEvidence {
			break
		}
		detail := direction + ": selected " + selectedRole + " pod"
		if result.allowing[policy.Name] {
			detail += "; allows this flow"
		} else if result.uncertain {
			detail += "; an IPBlock peer could not be evaluated"
		} else {
			detail += "; no rule allows this flow"
		}
		evidence = append(evidence, Evidence{
			Kind:      "NetworkPolicy",
			Namespace: policy.Namespace,
			Name:      policy.Name,
			Detail:    detail,
		})
	}
	return evidence
}

func suggestedPolicyFix(egressStatus, ingressStatus string) string {
	switch {
	case egressStatus == "denied" && ingressStatus == "denied":
		return "Add matching egress and ingress allow rules for the source, destination, protocol, and port."
	case egressStatus == "denied":
		return "Add an egress rule allowing the destination pod and port to a NetworkPolicy selecting the source pod."
	default:
		return "Add an ingress rule allowing the source pod and port to a NetworkPolicy selecting the destination pod."
	}
}

func policyInconclusive(reason, suggestedFix string) (Result, error) {
	return Result{
		Verdict:      VerdictInconclusive,
		Reason:       reason,
		SuggestedFix: suggestedFix,
	}, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	return unique
}

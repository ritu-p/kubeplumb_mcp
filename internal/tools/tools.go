// Package tools exposes the diagnose checks as MCP tools.
// Handlers stay thin: validate input, call diagnose, return the Result.
package tools

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/rituk/kubeplumb_mcp/internal/diagnose"
)

// callTimeout bounds every tool call so a slow API server cannot hang a session.
const callTimeout = 20 * time.Second

// Register adds every tool to the server.
func Register(s *mcp.Server, cs kubernetes.Interface) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "check_service",
		Description: "Check whether a Kubernetes Service can route traffic to a ready backend. " +
			"Verifies that the Service exists, exposes the port, has a selector that matches pods, " +
			"that those pods are Ready, that named targetPorts resolve, and that its EndpointSlices " +
			"hold ready endpoints. Read-only. Use it when a client gets timeouts, connection refused, " +
			"or 503s calling a Service. It does not evaluate NetworkPolicies or DNS.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, checkService(cs))

	mcp.AddTool(s, &mcp.Tool{
		Name: "check_dns",
		Description: "Check API-visible cluster DNS health. Verifies the kube-system/kube-dns " +
			"Service, its UDP and TCP port 53, selected pod readiness, and ready EndpointSlice endpoints. " +
			"It does not perform a DNS query or prove that a particular name resolves.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, checkDNS(cs))

	mcp.AddTool(s, &mcp.Tool{
		Name: "evaluate_network_policies",
		Description: "Evaluate standard Kubernetes NetworkPolicy ingress and egress rules for a specific " +
			"source pod to destination pod flow and destination port. Protocol defaults to TCP. " +
			"CNI-specific policy layers and actual packet delivery are not verified.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, evaluateNetworkPolicies(cs))
}

// CheckServiceInput is the argument schema for check_service.
type CheckServiceInput struct {
	Namespace string `json:"namespace" jsonschema:"namespace of the Service"`
	Service   string `json:"service" jsonschema:"name of the Service"`
	Port      int    `json:"port,omitempty" jsonschema:"service port the client connects to; omit to check every port"`
}

func checkService(cs kubernetes.Interface) mcp.ToolHandlerFor[CheckServiceInput, diagnose.Result] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CheckServiceInput) (*mcp.CallToolResult, diagnose.Result, error) {
		if in.Namespace == "" || in.Service == "" {
			return nil, diagnose.Result{}, errors.New("namespace and service are required")
		}
		if in.Port < 0 || in.Port > 65535 {
			return nil, diagnose.Result{}, errors.New("port must be between 1 and 65535")
		}
		ctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		res, err := diagnose.CheckService(ctx, cs, in.Namespace, in.Service, in.Port)
		return nil, res, err
	}
}

type CheckDNSInput struct{}

func checkDNS(cs kubernetes.Interface) mcp.ToolHandlerFor[CheckDNSInput, diagnose.Result] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ CheckDNSInput) (*mcp.CallToolResult, diagnose.Result, error) {
		ctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		res, err := diagnose.CheckDNS(ctx, cs)
		return nil, res, err
	}
}

type EvaluateNetworkPoliciesInput struct {
	SourceNamespace      string `json:"source_namespace" jsonschema:"namespace of the source pod"`
	SourcePod            string `json:"source_pod" jsonschema:"name of the source pod"`
	DestinationNamespace string `json:"destination_namespace" jsonschema:"namespace of the destination pod"`
	DestinationPod       string `json:"destination_pod" jsonschema:"name of the destination pod"`
	Port                 int    `json:"port" jsonschema:"destination port number from 1 through 65535"`
	Protocol             string `json:"protocol,omitempty" jsonschema:"TCP, UDP, or SCTP; defaults to TCP"`
}

func evaluateNetworkPolicies(cs kubernetes.Interface) mcp.ToolHandlerFor[EvaluateNetworkPoliciesInput, diagnose.Result] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in EvaluateNetworkPoliciesInput) (*mcp.CallToolResult, diagnose.Result, error) {
		if in.SourceNamespace == "" || in.SourcePod == "" ||
			in.DestinationNamespace == "" || in.DestinationPod == "" {
			return nil, diagnose.Result{}, errors.New("source and destination namespaces and pod names are required")
		}
		if in.Port < 1 || in.Port > 65535 {
			return nil, diagnose.Result{}, errors.New("destination port must be between 1 and 65535")
		}
		protocol := corev1.ProtocolTCP
		if in.Protocol != "" {
			protocol = corev1.Protocol(strings.ToUpper(strings.TrimSpace(in.Protocol)))
		}
		if protocol != corev1.ProtocolTCP &&
			protocol != corev1.ProtocolUDP &&
			protocol != corev1.ProtocolSCTP {
			return nil, diagnose.Result{}, errors.New("protocol must be TCP, UDP, or SCTP")
		}

		ctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		result, err := diagnose.EvaluateNetworkPolicies(ctx, cs, diagnose.NetworkPolicyFlow{
			SourceNamespace:      in.SourceNamespace,
			SourcePod:            in.SourcePod,
			DestinationNamespace: in.DestinationNamespace,
			DestinationPod:       in.DestinationPod,
			Port:                 in.Port,
			Protocol:             protocol,
		})
		return nil, result, err
	}
}

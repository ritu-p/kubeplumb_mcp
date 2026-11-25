// Package tools exposes the diagnose checks as MCP tools.
// Handlers stay thin: validate input, call diagnose, return the Result.
package tools

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

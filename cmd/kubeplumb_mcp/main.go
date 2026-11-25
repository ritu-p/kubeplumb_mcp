// Command kubeplumb_mcp is an MCP server that diagnoses pod connectivity
// problems in a Kubernetes cluster. It speaks MCP over stdio.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rituk/kubeplumb_mcp/internal/kube"
	"github.com/rituk/kubeplumb_mcp/internal/tools"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	kubeconfig := flag.String("kubeconfig", "", "path to a kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	kubeContext := flag.String("context", "", "kubeconfig context to use (default: the current context)")
	flag.Parse()

	// stdout carries the MCP protocol, so all logging must go to stderr.
	log.SetOutput(os.Stderr)
	log.SetPrefix("kubeplumb_mcp: ")

	cs, err := kube.NewClient(*kubeconfig, *kubeContext, "kubeplumb_mcp/"+version)
	if err != nil {
		log.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "kubeplumb_mcp", Version: version}, nil)
	tools.Register(server, cs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

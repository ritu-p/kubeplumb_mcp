# kubeplumb_mcp

An MCP server that tells on-call engineers **why pod A cannot reach service B** in a Kubernetes cluster.

Most Kubernetes MCP servers hand the model raw `kubectl` output and let it improvise. This one runs deterministic checks along the network path and returns a structured verdict with evidence, so the same question always gets the same answer.

Status: early scaffold. One tool works today.

## Tools

| Tool | Status | What it checks |
|---|---|---|
| `check_service` | Working | The Service exists, exposes the port, selects Ready pods, resolves named targetPorts, and has ready endpoints |
| `check_dns` | Planned | Name resolution and CoreDNS health |
| `evaluate_network_policies` | Planned | Whether egress from the source and ingress to the destination are allowed |
| `diagnose_connectivity` | Planned | Runs every check in path order and stops at the first failure |
| `run_probe` | Planned | Live connection test from an ephemeral container, behind user approval |

Every tool returns the same shape:

```json
{
  "verdict": "blocked",
  "failed_step": "service",
  "reason": "The selector of Service scenario-selector/web matches no pods.",
  "evidence": [{"kind": "Service", "namespace": "scenario-selector", "name": "web", "detail": "selector: app=wbe"}],
  "suggested_fix": "Compare the selector with the pod labels: kubectl get pods -n scenario-selector --show-labels"
}
```

## Quick start

Requires Go 1.24 or newer and access to a cluster through a kubeconfig.

```bash
go mod tidy          # first time only: resolves dependencies and writes go.sum
go test ./...
go build -o bin/kubeplumb_mcp ./cmd/kubeplumb_mcp
```

On Windows, build to `bin/kubeplumb_mcp.exe`.

### Try it on a broken cluster

```bash
./hack/kind-up.sh                                  # kind cluster with Calico
kubectl apply -f hack/scenarios/selector-mismatch.yaml
```

Then inspect the server with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector ./bin/kubeplumb_mcp
```

Call `check_service` with namespace `scenario-selector` and service `web`.

### Connect it to Claude

Claude Code:

```bash
claude mcp add kubeplumb_mcp -- /absolute/path/to/bin/kubeplumb_mcp --context kind-kubeplumb
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kubeplumb_mcp": {
      "command": "C:\\path\\to\\bin\\kubeplumb_mcp.exe",
      "args": ["--context", "kind-kubeplumb"]
    }
  }
}
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig file to load |
| `--context` | current context | Kubeconfig context to use |

With no kubeconfig present, the server uses the in-cluster service account.

## Security

The server only issues `get` and `list` calls. `deploy/rbac.yaml` holds the least-privilege ClusterRole it needs; it never reads Secrets.

## Layout

```
cmd/kubeplumb_mcp/   entrypoint: flags, client, stdio transport
internal/diagnose/   the checks; no MCP imports, tested with a fake clientset
internal/tools/      MCP tool definitions wrapping the checks
internal/kube/       Kubernetes client construction
deploy/              RBAC manifests
hack/                local cluster script and broken scenarios for the benchmark
```

To add a check: write the function and its tests in `internal/diagnose`, register it in `internal/tools/tools.go`, add any new permissions to `deploy/rbac.yaml`, and add a broken scenario under `hack/scenarios`.

// Package diagnose contains the deterministic connectivity checks.
// It knows nothing about MCP, so every check can be unit-tested with a fake
// Kubernetes clientset and reused from a CLI or benchmark harness.
package diagnose

const (
	// VerdictOK means the check found nothing that would stop traffic.
	VerdictOK = "ok"
	// VerdictBlocked means the check found a definite reason traffic fails.
	VerdictBlocked = "blocked"
	// VerdictInconclusive means the check could not decide from the API alone.
	VerdictInconclusive = "inconclusive"
)

// Step names identify where on the path a check failed.
const (
	StepService = "service"
)

// Result is the structured verdict every check returns.
type Result struct {
	Verdict      string     `json:"verdict" jsonschema:"one of: ok, blocked, inconclusive"`
	FailedStep   string     `json:"failed_step,omitempty" jsonschema:"the path step that failed, set when verdict is blocked"`
	Reason       string     `json:"reason" jsonschema:"one-sentence explanation of the verdict"`
	Evidence     []Evidence `json:"evidence,omitempty" jsonschema:"cluster objects that support the verdict"`
	Warnings     []string   `json:"warnings,omitempty" jsonschema:"findings that are suspicious but do not prove a failure"`
	SuggestedFix string     `json:"suggested_fix,omitempty" jsonschema:"what to change or check next"`
}

// Evidence points at one cluster object and says what about it matters.
type Evidence struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Detail    string `json:"detail,omitempty"`
}

// maxEvidence caps how many objects one result lists, to keep tool output small.
const maxEvidence = 10

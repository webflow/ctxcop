package codex

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type preToolUseInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type preToolUseOutput struct {
	HookSpecificOutput preToolUseHSO `json:"hookSpecificOutput"`
}

type preToolUseHSO struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// PreToolUse on Codex is deny-only: updatedInput is parsed but rejected
// at runtime (openai/codex#18491), so we can't transparently wrap Bash
// the way Claude Code does. Tool output redaction shifts to PostToolUse.
// Fail-open.
func PreToolUse(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in preToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if len(in.ToolInput) == 0 {
		return passthrough(w)
	}

	switch {
	case in.ToolName == "Bash":
		return denyIfCommandHasSecret(in.ToolName, in.ToolInput, w)
	case in.ToolName == "apply_patch":
		return denyIfCommandHasSecret(in.ToolName, in.ToolInput, w)
	case strings.HasPrefix(in.ToolName, "mcp__"):
		return denyIfMCPInputHasSecret(in.ToolName, in.ToolInput, w)
	default:
		return passthrough(w)
	}
}

func denyIfCommandHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input.Command == "" {
		return passthrough(w)
	}
	_, rules, err := redact.RedactWithMatches(input.Command)
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	reason := fmt.Sprintf(
		"ctxcop blocked the %s call: the command contains an apparent %s.\n"+
			"\n"+
			"Codex's hook system doesn't support transparent input rewriting today, so ctxcop "+
			"can't substitute a placeholder for you — re-issue the command with the secret referenced as an env var instead:\n"+
			"  - Export the value in your shell once, then call: `aws ... --token \"$AWS_TOKEN\" ...`. "+
			"The shell substitutes inside the child process; the literal never enters Codex's context.\n"+
			"  - For apply_patch, replace the literal with `${ENV_VAR}` / `process.env.X` / `os.Getenv(\"X\")` "+
			"depending on the target language, then have the runtime resolve it.\n"+
			"  - If this is genuinely a non-secret string that triggered the detector, prepend "+
			"`# gitleaks:allow` to the relevant line and retry.",
		tool, strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "Codex/" + tool, Action: "blocked", Rules: rules, Field: "command"})
	return emitDeny(w, reason)
}

func denyIfMCPInputHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input any
	if err := json.Unmarshal(raw, &input); err != nil {
		return passthrough(w)
	}
	hit, field, rules := redact.FirstHit(input)
	if !hit {
		return passthrough(w)
	}
	reason := fmt.Sprintf(
		"ctxcop blocked %s: input field %q contains an apparent %s.\n"+
			"\n"+
			"MCP servers run as separate processes. Forwarding a credential through tool_input "+
			"both writes it into your context and hands it to a process that may persist or relay it. "+
			"Configure the MCP server's auth in its own environment block, not via tool_input.",
		tool, field, strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: tool, Action: "blocked", Rules: rules, Field: field})
	return emitDeny(w, reason)
}

func emitDeny(w io.Writer, reason string) error {
	out := preToolUseOutput{
		HookSpecificOutput: preToolUseHSO{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

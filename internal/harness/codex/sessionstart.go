package codex

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/pause"
)

const primingMessage = `ctxcop is active in this Codex session. Tool input is scanned for credential-shape data; credential-bearing inputs are denied via PreToolUse, and tool responses containing credential-shape data are BLOCKED from reaching your context via PostToolUse (with a reason describing what was caught). Conventions:
- Shell: reference secrets via $ENV_VAR — the child shell substitutes, the value never enters your tokens. ctxcop cannot transparently wrap Codex's shell tool, so input-level $ENV_VAR discipline matters more here than in Claude Code.
- Code (apply_patch / Edit / Write): emit ` + "`process.env.X` / `os.Getenv(\"X\")`" + ` / config-template placeholders, never literal credentials.
- If ctxcop blocks a tool response, the underlying tool already executed — file writes, shell exits, MCP server state have happened. What's blocked is the LITERAL response value reaching your context. If the credential surfaced unexpectedly, rotate it.
- Caveats:
  - Hooks fire only for the standard shell tool payload (single ` + "`command`" + ` string). unified_exec, local_shell, and streaming shell variants currently bypass ctxcop with no notification — treat their output with caution.
  - Codex's in-place response redaction (updatedMCPToolOutput) is "parsed but not supported yet" today, so ctxcop blocks the whole response rather than selectively redact. The trade-off: cleaner safety semantics, less granular than Claude Code's per-string redaction.`

type sessionStartOutput struct {
	HookSpecificOutput sessionStartHSO `json:"hookSpecificOutput"`
}

type sessionStartHSO struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// SessionStart emits the Codex priming. Fail-open.
func SessionStart(w io.Writer) error {
	ctx := primingMessage
	if banner := pause.Banner(); banner != "" {
		ctx = banner + "\n\n" + ctx
	}
	out := sessionStartOutput{
		HookSpecificOutput: sessionStartHSO{
			HookEventName:     "SessionStart",
			AdditionalContext: ctx,
		},
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		_, _ = io.WriteString(w, "{}\n")
	}
	return nil
}

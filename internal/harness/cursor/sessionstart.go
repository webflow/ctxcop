package cursor

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/pause"
)

const primingMessage = `ctxcop is active in this Cursor session. Tool input is scanned for credential-shape data; credential-bearing inputs are denied via preToolUse, and MCP tool responses are redacted via postToolUse's updated_mcp_tool_output. Conventions:
- Shell: reference secrets via $ENV_VAR — the child shell substitutes, the value never enters your tokens.
- Write/Edit: emit ` + "`process.env.X` / `os.Getenv(\"X\")`" + ` / config-template placeholders, never literal credentials.
- A ` + "`<REDACTED:…>`" + ` placeholder means the value never reached you — don't pipe through base64/xxd to recover it.
- Caveats:
  - WebSearch and AskQuestion bypass Cursor hooks today (Auto-mode and built-in bug, open as of May 2026). Treat their output with caution.
  - Cursor's agent-loop file exploration ("Explored N files" / inline file reads triggered by short user prompts like "read test") can surface file content WITHOUT firing preToolUse. This was verified empirically: direct ` + "`Read`" + ` tool calls are gated and credential-bearing files get redirected to a redacted temp copy; agent-loop reads bypass that gate. If you see a credential-shape value appear from a Cursor file-exploration step, treat it as unredacted and rotate it.
  - Tool-output redaction via updated_mcp_tool_output is documented as generic but reliably consumed only by MCP-prefixed tools; built-in tool responses bypass the override. Read files are pre-emptively redirected (preToolUse + updated_input) to compensate.`

type sessionStartOutput struct {
	AdditionalContext string `json:"additional_context,omitempty"`
}

// SessionStart emits the priming message. Cursor body fields are snake_case
// even though event names are camelCase. Note: additional_context is parsed
// but not surfaced to the agent window today (forum 157141, open); ctxcop's
// security guarantees don't depend on this reaching the model. Fail-open.
func SessionStart(w io.Writer) error {
	ctx := primingMessage
	if banner := pause.Banner(); banner != "" {
		ctx = banner + "\n\n" + ctx
	}
	out := sessionStartOutput{AdditionalContext: ctx}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		_, _ = io.WriteString(w, "{}\n")
	}
	return nil
}

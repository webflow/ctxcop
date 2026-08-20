package claudecode

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/pause"
)

// primingMessage is what Claude sees at session start. Kept short on purpose —
// it costs tokens every session. Goal: install the canonical patterns up front
// so the agent doesn't have to discover them from per-event hook denials.
const primingMessage = `ctxcop is active in this session. Tool output is auto-redacted (you'll see ` + "`<REDACTED:rule-id:last4>`" + ` placeholders, or ` + "`<REDACTED:rule-id>`" + ` when the value is too short to fingerprint without disclosing it) and tool inputs containing credentials are blocked. Default to these patterns to avoid pulling secrets into your context:
- Shell: reference secrets via $ENV_VAR — the child shell substitutes; the value never enters your tokens.
- Code (Write/Edit): emit ` + "`process.env.X` / `os.Getenv(\"X\")`" + ` / config-template placeholders, never literal credentials.
- HTTP auth: use Bash + curl with ` + "`Authorization: Bearer $TOKEN`" + `, not WebFetch with the token in the URL.
- Project the field you actually need: ` + "`aws sts get-caller-identity --query 'Arn'`" + ` over the whole response.
- A ` + "`<REDACTED:…>`" + ` placeholder means the value never reached you — don't pipe through base64/xxd to recover it.
- MCP forms (elicitation): never type credentials into a form-mode field — the MCP spec forbids it for that reason. If you see a ctxcop notice flagging form-mode credential input, treat the value as compromised and rotate it.
- Context compaction: if a compaction summary surfaces credential-shaped text, treat it as if it were the unredacted source — don't propagate it. ctxcop flags this via systemMessage at compact time.`

type sessionStartOutput struct {
	HookSpecificOutput sessionStartHSO `json:"hookSpecificOutput"`
}

type sessionStartHSO struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// SessionStart emits the priming additionalContext for Claude to read at the
// start of every session. Always fail-open: any error returns "{}\n" so a
// broken SessionStart hook never prevents a session from starting.
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

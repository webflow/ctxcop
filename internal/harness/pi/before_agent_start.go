package pi

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/pause"
)

const primingMessage = `ctxcop is active in this session. Every LLM payload is scanned for credentials immediately before send; ` + "`<REDACTED:rule-id:last4>`" + ` placeholders (or ` + "`<REDACTED:rule-id>`" + ` for values too short to fingerprint without disclosing them) mean a credential was found and redacted. To avoid pulling secrets into your context:
- Shell: reference secrets via $ENV_VAR — the child shell substitutes; the value never enters your tokens.
- Code (edit/write): emit ` + "`process.env.X` / `os.Getenv(\"X\")`" + ` / config-template placeholders, never literal credentials.
- HTTP auth: use bash + curl with ` + "`Authorization: Bearer $TOKEN`" + `, not URLs that embed the token.
- Project the field you actually need: ` + "`aws sts get-caller-identity --query 'Arn'`" + ` over the whole response.
- A ` + "`<REDACTED:…>`" + ` placeholder means the value never reached you — don't pipe through base64/xxd to recover it.
- MCP tools that take credential-shaped input are blocked at tool_call before they execute; configure the MCP server's auth server-side instead of passing it through the tool call.`

type beforeAgentStartInput struct {
	SystemPrompt string `json:"systemPrompt"`
}

type beforeAgentStartOutput struct {
	SystemPrompt string `json:"systemPrompt"`
}

// BeforeAgentStart appends ctxcop's priming text to the system prompt.
// Bridge gates this to once per session. Fail-open on any error.
func BeforeAgentStart(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in beforeAgentStartInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	out := beforeAgentStartOutput{
		SystemPrompt: in.SystemPrompt + "\n\n" + primingMessage,
	}
	if banner := pause.Banner(); banner != "" {
		out.SystemPrompt = in.SystemPrompt + "\n\n" + banner + "\n\n" + primingMessage
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

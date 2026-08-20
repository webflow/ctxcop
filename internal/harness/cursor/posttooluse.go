package cursor

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type postToolUseInput struct {
	ToolName   string          `json:"tool_name"`
	ToolOutput json.RawMessage `json:"tool_output"`
}

// additional_context omitted intentionally: Cursor parses it but doesn't
// surface it to the model (forum 155689, open).
type postToolUseOutput struct {
	UpdatedMCPToolOutput any `json:"updated_mcp_tool_output,omitempty"`
}

// PostToolUse redacts tool_output via updated_mcp_tool_output. Reliably
// honored only for MCP-prefixed tools per docs/known-limits.md; best-effort
// for built-ins. Fail-open.
func PostToolUse(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in postToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if len(in.ToolOutput) == 0 {
		return passthrough(w)
	}
	// tool_output may be a JSON value or a JSON-stringified value; unwrap once.
	var resp any
	if err := json.Unmarshal(in.ToolOutput, &resp); err != nil {
		return passthrough(w)
	}
	if s, ok := resp.(string); ok {
		var inner any
		if err := json.Unmarshal([]byte(s), &inner); err == nil {
			resp = inner
		} else {
			resp = s
		}
	}

	// Tool output is untrusted — do not honor inline allow/fixture markers.
	redacted, ruleIDs := redact.RedactTreeToolOutput(resp)
	if len(ruleIDs) == 0 {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "Cursor/" + in.ToolName,
		Action: "redacted",
		Rules:  ruleIDs,
		Count:  len(ruleIDs),
	})
	out := postToolUseOutput{UpdatedMCPToolOutput: redacted}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

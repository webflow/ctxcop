package opencode

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type toolExecuteAfterInput struct {
	Tool      string `json:"tool"`
	SessionID string `json:"sessionID"`
	CallID    string `json:"callID"`
	Args      any    `json:"args"`
	Output    string `json:"output"`
}

type toolExecuteAfterOutput struct {
	Output string `json:"output,omitempty"`
}

// ToolExecuteAfter redacts credential-shape data from a tool's output
// string before it lands in the message stream the model sees next
// turn. Per OpenCode plugin docs, output.output is always a string.
// Fail-open on any error.
func ToolExecuteAfter(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in toolExecuteAfterInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if in.Output == "" {
		return passthrough(w)
	}
	// Tool output is untrusted — do not honor inline allow/fixture markers.
	redacted, rules, err := redact.RedactToolOutput(in.Output)
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "OpenCode:tool.execute.after",
		Action: "redacted",
		Rules:  rules,
		Count:  len(rules),
		Field:  in.Tool,
	})
	out := toolExecuteAfterOutput{Output: redacted}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

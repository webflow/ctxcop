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
	Metadata  any    `json:"metadata"`
}

type toolExecuteAfterOutput struct {
	Output   string `json:"output,omitempty"`
	Metadata any    `json:"metadata,omitempty"`
}

// ToolExecuteAfter redacts credential-shape data from a tool's output
// string before it lands in the message stream the model sees next
// turn, and from output.metadata, which OpenCode persists to the
// session store (and includes in `--format json` / `opencode export`)
// independently of output.output — a raw copy of a tool's stdout
// survives there even when output.output is fully redacted. Fail-open
// on any error.
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
	if in.Output == "" && in.Metadata == nil {
		return passthrough(w)
	}

	var out toolExecuteAfterOutput
	var allRules []string

	// Tool output is untrusted — do not honor inline allow/fixture markers.
	if in.Output != "" {
		if redacted, rules, err := redact.RedactToolOutput(in.Output); err == nil && len(rules) > 0 {
			out.Output = redacted
			allRules = append(allRules, rules...)
		}
	}
	if in.Metadata != nil {
		if redacted, rules := redact.RedactTreeToolOutput(in.Metadata); len(rules) > 0 {
			out.Metadata = redacted
			allRules = append(allRules, rules...)
		}
	}
	if len(allRules) == 0 {
		return passthrough(w)
	}

	audit.Log(audit.Entry{
		Tool:   "OpenCode:tool.execute.after",
		Action: "redacted",
		Rules:  allRules,
		Count:  len(allRules),
		Field:  in.Tool,
	})
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

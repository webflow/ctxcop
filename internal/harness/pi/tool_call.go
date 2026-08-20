package pi

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type toolCallInput struct {
	ToolName   string `json:"toolName"`
	ToolCallID string `json:"toolCallId"`
	Input      any    `json:"input"`
}

type toolCallOutput struct {
	Block  bool   `json:"block,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ToolCall blocks MCP tool calls whose input carries credential-shape
// data — the only path on Pi where data leaves the box without
// crossing the before_provider_request chokepoint. Fail-open on any
// error.
func ToolCall(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in toolCallInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if !strings.HasPrefix(in.ToolName, "mcp__") {
		return passthrough(w)
	}
	if in.Input == nil {
		return passthrough(w)
	}
	rules, fields := redact.AllHits(in.Input)
	if len(rules) == 0 {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "Pi:tool_call",
		Action: "blocked",
		Rules:  rules,
		Count:  len(rules),
		Field:  in.ToolName + ":" + strings.Join(fields, ","),
	})
	reason := fmt.Sprintf(
		"ctxcop: blocked MCP tool call %q — credential-shape data (%s) found in input field(s): %s. "+
			"Configure the MCP server's auth server-side (env block in .mcp.json) "+
			"rather than forwarding the credential through the tool call. "+
			"Retry with the credential removed from tool_input.",
		in.ToolName,
		strings.Join(rules, ", "),
		strings.Join(fields, ", "),
	)
	out := toolCallOutput{Block: true, Reason: reason}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

package opencode

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type toolExecuteBeforeInput struct {
	Tool      string `json:"tool"`
	SessionID string `json:"sessionID"`
	CallID    string `json:"callID"`
	Args      any    `json:"args"`
}

type toolExecuteBeforeOutput struct {
	Block  bool   `json:"block,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Built-in opencode tools that operate locally and don't exfiltrate.
// MCP tools are emitted as "<server>_<tool>" — anything not in this
// set and containing an underscore is treated as MCP-class.
//
// apply_patch is listed explicitly despite its underscore: it's an
// alternate local edit path (same semantics as edit/write), not an
// MCP tool, and would otherwise be misclassified as exfil-class by
// the underscore heuristic below and false-positive block on
// legitimate patches.
var localTools = map[string]struct{}{
	"bash":        {},
	"read":        {},
	"write":       {},
	"edit":        {},
	"apply_patch": {},
	"grep":        {},
	"glob":        {},
	"ls":          {},
	"todoread":    {},
	"todowrite":   {},
	"task":        {},
}

// exfilTools are built-in (non-MCP) tools whose input fields cross the
// box boundary on call, same reasoning as webfetch: a credential here
// leaves the machine immediately, before tool.execute.after ever runs.
var exfilTools = map[string]struct{}{
	"webfetch":  {},
	"websearch": {},
}

// isExfilClass returns true for tools whose input fields cross the box
// boundary on call — webfetch/websearch and MCP tools. A credential here
// leaves the machine immediately; redacting at tool.execute.after is too late.
func isExfilClass(tool string) bool {
	t := strings.ToLower(tool)
	if _, ok := exfilTools[t]; ok {
		return true
	}
	if _, ok := localTools[t]; ok {
		return false
	}
	return strings.Contains(t, "_")
}

// ToolExecuteBefore blocks exfil-class tool calls (webfetch, MCP) whose
// args carry credential-shape data. Local tools (bash, read, write, etc.)
// passthrough; their output is redacted on the after hook. Fail-open on
// any error.
func ToolExecuteBefore(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in toolExecuteBeforeInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if !isExfilClass(in.Tool) || in.Args == nil {
		return passthrough(w)
	}
	rules, fields := redact.AllHits(in.Args)
	if len(rules) == 0 {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "OpenCode:tool.execute.before",
		Action: "blocked",
		Rules:  rules,
		Count:  len(rules),
		Field:  in.Tool + ":" + strings.Join(fields, ","),
	})
	reason := fmt.Sprintf(
		"ctxcop: blocked tool call %q — credential-shape data (%s) found in input field(s): %s. "+
			"Configure the tool's auth server-side rather than forwarding the credential through the call. "+
			"Retry with the credential removed from the args.",
		in.Tool,
		strings.Join(rules, ", "),
		strings.Join(fields, ", "),
	)
	out := toolExecuteBeforeOutput{Block: true, Reason: reason}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

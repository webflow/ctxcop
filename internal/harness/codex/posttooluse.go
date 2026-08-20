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

type postToolUseInput struct {
	ToolName     string          `json:"tool_name"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

// postToolUseBlock uses top-level decision+reason. hookSpecificOutput.
// updatedMCPToolOutput is in the schema but fails open today (Codex docs:
// "parsed but not supported yet"); relying on it would silently leak.
type postToolUseBlock struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// PostToolUse blocks credential-bearing tool responses from reaching the
// model. The tool already executed — side effects are not undone. When
// Codex ships output-mutation support, escalate to in-place redaction
// gated on a version check. Fail-open.
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
	if len(in.ToolResponse) == 0 {
		return passthrough(w)
	}
	var resp any
	if err := json.Unmarshal(in.ToolResponse, &resp); err != nil {
		// Plain-text response — scan as a string.
		resp = string(in.ToolResponse)
	}
	// Tool responses are untrusted — do not honor inline allow/fixture markers.
	ruleIDs, fields := redact.AllHitsToolOutput(resp)
	if len(ruleIDs) == 0 {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "Codex/" + in.ToolName,
		Action: "blocked",
		Rules:  ruleIDs,
		Count:  len(ruleIDs),
		Field:  strings.Join(fields, ","),
	})
	reason := fmt.Sprintf(
		"ctxcop blocked the %s response: it contains apparent credential-shape data "+
			"(%s) at %s.\n"+
			"\n"+
			"The tool already executed (side effects, if any, have happened) — what's blocked "+
			"is the literal response value reaching your context. If the credential surfaced "+
			"unexpectedly, rotate it before continuing; the value also reached whatever the "+
			"tool's downstream consumer is (file system, MCP server, etc.) and may be logged "+
			"there. If you intended to retrieve a credential via this tool (vault, secrets-"+
			"manager, etc.), don't echo it, don't write it to other tools' inputs, and ask "+
			"the user to confirm before proceeding.\n"+
			"\n"+
			"Note: Codex's hook system does not yet support in-place response redaction "+
			"(updatedMCPToolOutput is parsed-but-not-supported as of May 2026). ctxcop blocks "+
			"the entire response rather than try to redact selectively.",
		in.ToolName,
		strings.Join(ruleIDs, ", "),
		strings.Join(fields, ", "))
	out := postToolUseBlock{Decision: "block", Reason: reason}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

package claudecode

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/audit"
)

// elicitationInput matches the actual Claude Code 2.1.x payload shape
// for the Elicitation hook (verified empirically in testing/elicit-mcp/;
// originally tracked in issue #5). The relevant field is
// `mcp_server_name` — there is no per-tool name, and the optional
// `mode` field distinguishes "form" (in-app structured input) from
// "url" (out-of-band capture introduced by draft 2025-11-25).
type elicitationInput struct {
	MCPServerName string          `json:"mcp_server_name"`
	Mode          string          `json:"mode"`
	Request       json.RawMessage `json:"request"`
	HookEventName string          `json:"hook_event_name"`
}

// Elicitation fires when an MCP server requests structured user input (form
// fields) mid-tool-call. The hook receives the request descriptor — field
// labels, types, prompts — BEFORE the user sees the form.
//
// ctxcop's value-add on this event is limited: the request comes from the
// MCP server, not from user data, so credential leakage is improbable here.
// We pass through with an audit entry so multi-harness deployments have a
// record that an MCP elicitation occurred. The chokepoint for credentials
// in elicitations is ElicitationResult (which scans the USER'S answer
// before it's transmitted back to the MCP server).
//
// Future: we could refuse elicitations from non-allowlisted MCP servers
// here, or pre-populate `content` to short-circuit user input. Out of
// scope for v0.2.0 — fail-open observation only.
func Elicitation(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in elicitationInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	field := in.MCPServerName
	if in.Mode != "" {
		field = field + "(" + in.Mode + ")"
	}
	audit.Log(audit.Entry{
		Tool:   "Elicitation",
		Action: "observed",
		Field:  field,
	})
	return passthrough(w)
}

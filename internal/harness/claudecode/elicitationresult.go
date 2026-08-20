package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

// elicitationResultInput matches the actual Claude Code 2.1.x payload
// shape (verified empirically in testing/elicit-mcp/; originally tracked
// in issue #5). The previous struct used `server_name` and `tool_name`,
// which never appeared on the wire — so ServerName always unmarshaled
// empty and the systemMessage notice rendered `MCP server ""` with
// literal empty quotes. The `mode` field is also new in the 2025-11-25
// draft elicitation spec: "form" = in-app structured input, "url" =
// out-of-band capture (the spec's safe path for credentials).
type elicitationResultInput struct {
	MCPServerName string         `json:"mcp_server_name"`
	Mode          string         `json:"mode"`
	Action        string         `json:"action"`
	Content       map[string]any `json:"content"`
	HookEventName string         `json:"hook_event_name"`
}

// elicitationResultNotice is the top-level shape we emit when we want to
// surface a notice to both the user and the model without modifying the
// form submission. `systemMessage` is the universal field for this; nesting
// under hookSpecificOutput would imply we want to override action/content.
type elicitationResultNotice struct {
	SystemMessage string `json:"systemMessage,omitempty"`
}

// ElicitationResult fires after the user has answered an MCP elicitation
// form, before the response is transmitted to the MCP server.
//
// Behavior (observe-only): scan `content`, audit-log findings, and emit
// a top-level `systemMessage` that points both audiences at the spec
// and explains the failure mode. Never modifies `content` — no risk of
// breaking a legitimate (if spec-violating) MCP flow. The empirical
// verification in testing/elicit-mcp/ confirmed that `content` does
// NOT reach the model's transcript or context window (it's routed only
// to the originating MCP server), so observe-only is correct.
//
// URL-mode elicitations (the spec's recommended path for credential
// capture) are passthrough — the credential goes through an out-of-band
// channel that doesn't reach the LLM context, and emitting our
// "consider migrating to URL-mode" warning when the user is already on
// URL-mode would be backwards.
//
// Fail-open on every error.
func ElicitationResult(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in elicitationResultInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	// URL-mode elicitation is the spec-recommended safe path for
	// credential capture — passthrough unconditionally. Same passthrough
	// covers decline/cancel and empty submissions (no content going to
	// the MCP server, nothing to scan).
	if in.Mode == "url" || in.Action != "accept" || len(in.Content) == 0 {
		return passthrough(w)
	}

	flaggedFields := []string{}
	allRules := map[string]struct{}{}
	for k, v := range in.Content {
		s, ok := v.(string)
		if !ok {
			continue
		}
		_, rules, err := redact.RedactWithMatches(s)
		if err != nil || len(rules) == 0 {
			continue
		}
		flaggedFields = append(flaggedFields, k)
		for _, r := range rules {
			allRules[r] = struct{}{}
		}
	}
	if len(flaggedFields) == 0 {
		return passthrough(w)
	}

	sort.Strings(flaggedFields)
	ruleIDs := make([]string, 0, len(allRules))
	for r := range allRules {
		ruleIDs = append(ruleIDs, r)
	}
	sort.Strings(ruleIDs)

	audit.Log(audit.Entry{
		Tool:   "ElicitationResult",
		Action: "form-credential-detected",
		Rules:  ruleIDs,
		Count:  len(ruleIDs),
		Field:  in.MCPServerName + ":" + strings.Join(flaggedFields, ","),
	})

	// Render the server label so the notice reads naturally regardless
	// of whether Claude Code populated `mcp_server_name`. Empty quotes
	// ("") in user-facing copy is the kind of UX rough edge that erodes
	// trust in a security tool.
	serverLabel := "the MCP server"
	if in.MCPServerName != "" {
		serverLabel = fmt.Sprintf("MCP server %q", in.MCPServerName)
	}

	notice := fmt.Sprintf(
		"ctxcop notice: %s accepted a form-mode elicitation containing apparent "+
			"credential-shape data (%s) in field(s): %s.\n"+
			"\n"+
			"The MCP specification (https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation, "+
			"\"Security and Trust\") forbids form-mode elicitations from carrying passwords, API keys, "+
			"access tokens, or payment credentials. Form mode is for non-sensitive structured input only. "+
			"For credential capture the spec defines URL-mode elicitation (draft 2025-11-25), which keeps "+
			"the credential out of the LLM context and out of the MCP transport entirely.\n"+
			"\n"+
			"If the submission was intentional: the server is using the wrong mechanism for credential input. "+
			"Consider filing an issue with its authors asking them to migrate to URL-mode (when available) "+
			"or to use an out-of-band auth flow. Either way, the literal value has now reached the MCP "+
			"server through a path the spec disallows — rotate the credential and don't rely on it remaining "+
			"private.\n"+
			"\n"+
			"If the submission was unintentional (user typed a credential into a field that wasn't asking "+
			"for one): same rotation recommendation; the MCP server already has the literal value.\n"+
			"\n"+
			"ctxcop did not modify the form submission — it has been transmitted to the MCP server as-is. "+
			"This notice is observation-only.",
		serverLabel,
		strings.Join(ruleIDs, ", "),
		strings.Join(flaggedFields, ", "),
	)

	out := elicitationResultNotice{SystemMessage: notice}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

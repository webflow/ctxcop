package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type postToolUseInput struct {
	ToolName     string          `json:"tool_name"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

type postToolUseOutput struct {
	HookSpecificOutput postToolUseHSO `json:"hookSpecificOutput"`
}

type postToolUseHSO struct {
	HookEventName     string          `json:"hookEventName"`
	AdditionalContext string          `json:"additionalContext,omitempty"`
	UpdatedToolOutput json.RawMessage `json:"updatedToolOutput,omitempty"`
}

// PostToolUse redacts credential-shape data from tool_response via
// updatedToolOutput (documented at code.claude.com/docs/en/hooks as
// "replaces the tool's result") and pairs it with an additionalContext
// notice — belt-and-suspenders for Claude Code versions or tools that
// don't honor the mutation, and for the case where fail-open swallowed
// an encode error. Skipped: Bash/Read (covered at PreToolUse),
// CTXCOP_POSTTOOLUSE_ALLOW matches (intentional secret-store reads —
// mutating those would break the workflow), CTXCOP_POSTTOOLUSE=off.
// Fail-open.
func PostToolUse(r io.Reader, w io.Writer) error {
	if strings.EqualFold(os.Getenv("CTXCOP_POSTTOOLUSE"), "off") {
		return passthrough(w)
	}
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
	switch in.ToolName {
	case "", "Bash", "Read":
		return passthrough(w)
	}
	if len(in.ToolResponse) == 0 {
		return passthrough(w)
	}

	// Plain-text responses bypass JSON parse; scan the raw bytes instead
	// of passing through — silent bypass on parse failure is a leak path.
	var resp any
	if err := json.Unmarshal(in.ToolResponse, &resp); err != nil {
		resp = string(in.ToolResponse)
	}
	// Tool responses are untrusted — do not honor inline allow/fixture markers
	// (issue #56).
	hits, where, rules := redact.FirstHitToolOutput(resp)
	if !hits {
		return passthrough(w)
	}

	if isAllowlisted(in.ToolName) {
		audit.Log(audit.Entry{Tool: in.ToolName, Action: "warned-suppressed", Rules: rules, Field: where})
		return passthrough(w)
	}

	redacted, _ := redact.RedactTreeToolOutput(resp)
	updated, err := json.Marshal(redacted)
	if err != nil {
		return passthrough(w)
	}

	notice := fmt.Sprintf(
		"ctxcop notice: the previous %s response included credential-pattern data (rule: %s) at %q. "+
			"ctxcop has substituted a <REDACTED:...> placeholder for the value; if your Claude Code "+
			"client doesn't yet honor tool-output rewrites and you still see the literal value above, "+
			"handle the value with care: don't echo it into chat, don't write it to a file, don't copy "+
			"it into subsequent tool inputs, and rotate it if this was unintentional. "+
			"To suppress this notice for tools you control (e.g. an intentional secret-store read), "+
			"set CTXCOP_POSTTOOLUSE_ALLOW (comma-separated globs).",
		in.ToolName, strings.Join(rules, ", "), where)
	audit.Log(audit.Entry{Tool: in.ToolName, Action: "redacted", Rules: rules, Field: where})

	out := postToolUseOutput{
		HookSpecificOutput: postToolUseHSO{
			HookEventName:     "PostToolUse",
			AdditionalContext: notice,
			UpdatedToolOutput: updated,
		},
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

// isAllowlisted matches against CTXCOP_POSTTOOLUSE_ALLOW (comma-separated
// globs, only `*` is special).
func isAllowlisted(tool string) bool {
	raw := os.Getenv("CTXCOP_POSTTOOLUSE_ALLOW")
	if raw == "" {
		return false
	}
	for _, pat := range strings.Split(raw, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if globMatch(pat, tool) {
			return true
		}
	}
	return false
}

// globMatch: only `*` is special, matches any run (including empty).
func globMatch(pat, s string) bool {
	if !strings.Contains(pat, "*") {
		return pat == s
	}
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	rest := s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(rest, parts[i])
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(parts[i]):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(rest, last)
}

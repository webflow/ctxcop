package claudecode

import (
	"os"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
)

// devModeWarn reports whether $CTXCOP_DEV=warn — opt-in audit-don't-block
// for content scanners. UserPromptSubmit and Bash/Read paths are unaffected.
func devModeWarn() bool {
	return strings.EqualFold(os.Getenv("CTXCOP_DEV"), "warn")
}

// blockOrWarn renders the PreToolUse response for a content-scan hit.
// In dev-warn mode the call is allowed with the reason surfaced; the audit
// action "blocked-downgraded" distinguishes it from real-time denials.
func blockOrWarn(tool, field, reason string, rules []string) hookOutput {
	if devModeWarn() {
		audit.Log(audit.Entry{Tool: tool, Action: "blocked-downgraded", Rules: rules, Field: field})
		return hookOutput{HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: "ctxcop dev-warn: would have blocked — " + reason,
		}}
	}
	audit.Log(audit.Entry{Tool: tool, Action: "blocked", Rules: rules, Field: field})
	return hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
}

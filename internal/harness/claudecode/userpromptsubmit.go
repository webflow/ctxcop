package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type userPromptSubmitInput struct {
	Prompt string `json:"prompt"`
}

// userPromptSubmitBlock uses top-level decision+reason — different shape
// from PreToolUse's nested hookSpecificOutput.permissionDecision. Getting
// the shape wrong fails silent; see docs/hook-contracts.md and the
// TestUserPromptBlocksOnSecret regression.
type userPromptSubmitBlock struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type userPromptSubmitNotice struct {
	HookSpecificOutput userPromptSubmitHSO `json:"hookSpecificOutput"`
}

type userPromptSubmitHSO struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// UserPromptSubmit blocks the prompt if it contains apparent secrets.
// The raw prompt does not enter Claude's context on block — this is the
// chokepoint for "user pastes a credential into chat". Fail-open.
func UserPromptSubmit(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in userPromptSubmitInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if in.Prompt == "" {
		return passthrough(w)
	}
	if pause.IsPaused() {
		return emitPausedNotice(w)
	}
	_, rules, err := redact.RedactWithMatches(in.Prompt)
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	reason := fmt.Sprintf(
		"ctxcop blocked your prompt: it contains an apparent %s.\n"+
			"\n"+
			"Pasting a credential into chat puts the literal value into Claude's context window and (often) the transcript on disk. Re-submit with one of:\n"+
			"  - The secret removed entirely; reference it abstractly (\"my production AWS access key\").\n"+
			"  - The secret loaded into an env var in your shell first, then have Claude run commands that use $YOUR_VAR — the value never enters the conversation.\n"+
			"  - If this is genuinely a non-secret string that triggered the detector, prepend the word `gitleaks:allow` somewhere in your message and re-submit.",
		strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "UserPromptSubmit", Action: "blocked", Rules: rules, Field: "prompt"})

	out := userPromptSubmitBlock{
		Decision: "block",
		Reason:   reason,
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

// emitPausedNotice surfaces the pause banner via non-blocking
// additionalContext — prompt proceeds, model sees the banner.
func emitPausedNotice(w io.Writer) error {
	banner := pause.Banner()
	if banner == "" {
		return passthrough(w)
	}
	out := userPromptSubmitNotice{
		HookSpecificOutput: userPromptSubmitHSO{
			HookEventName:     "UserPromptSubmit",
			AdditionalContext: banner,
		},
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

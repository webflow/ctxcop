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

type userPromptSubmitInput struct {
	Prompt string `json:"prompt"`
}

// userPromptSubmitBlock matches both Codex's canonical top-level shape
// (`{decision, reason}`) AND the Claude Code shape, since the research
// confirms Codex parses both. We use top-level fields to keep the
// contract identical across harnesses where possible.
type userPromptSubmitBlock struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// userPromptSubmitNotice is the non-blocking shape: top-level
// additionalContext without a decision. Codex parses the same shape as
// Claude Code on this field; the model sees the banner alongside the
// user's prompt, the prompt itself is untouched.
type userPromptSubmitNotice struct {
	HookSpecificOutput userPromptSubmitHSO `json:"hookSpecificOutput"`
}

type userPromptSubmitHSO struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// UserPromptSubmit blocks the prompt if it contains credential-shape
// data. The contract is the same as Claude Code's UserPromptSubmit:
// top-level `decision: "block"` + `reason`. Codex parses this shape
// directly (verified against the wire schema in
// codex-rs/hooks/schema/generated/user-prompt-submit.command.output.schema.json).
//
// Fail-open on every error path.
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
			"Pasting a credential into chat puts the literal value into Codex's context window and the transcript on disk. Re-submit with one of:\n"+
			"  - The secret removed entirely; reference it abstractly (\"my production AWS access key\").\n"+
			"  - The secret loaded into an env var in your shell first, then have Codex run commands that use $YOUR_VAR — the value never enters the conversation.\n"+
			"  - If this is genuinely a non-secret string that triggered the detector, prepend the word `gitleaks:allow` somewhere in your message and re-submit.",
		strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "Codex/UserPromptSubmit", Action: "blocked", Rules: rules, Field: "prompt"})

	out := userPromptSubmitBlock{Decision: "block", Reason: reason}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

func passthrough(w io.Writer) error {
	_, _ = io.WriteString(w, "{}\n")
	return nil
}

// emitPausedNotice surfaces the paused banner via non-blocking
// additionalContext. Same role as the Claude Code equivalent.
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

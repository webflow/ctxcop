package cursor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type beforeSubmitPromptInput struct {
	Prompt string `json:"prompt"`
}

// beforeSubmitPromptOutput uses Cursor's flat block shape. continue:false
// halts; user_message is surfaced to the user (additional_context isn't,
// forum 155689 / 157141).
type beforeSubmitPromptOutput struct {
	Continue    bool   `json:"continue"`
	UserMessage string `json:"user_message,omitempty"`
}

// BeforeSubmitPrompt blocks credential-bearing prompts. Fail-open.
func BeforeSubmitPrompt(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in beforeSubmitPromptInput
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
	msg := fmt.Sprintf(
		"ctxcop blocked your prompt: it contains an apparent %s.\n"+
			"\n"+
			"Pasting a credential into chat puts the literal value into Cursor's context window and the transcript on disk. Re-submit with one of:\n"+
			"  - The secret removed entirely; reference it abstractly (\"my production AWS access key\").\n"+
			"  - The secret loaded into an env var in your shell first, then have Cursor run commands that use $YOUR_VAR.\n"+
			"  - If this is genuinely a non-secret string that triggered the detector, prepend the word `gitleaks:allow` somewhere in your message and re-submit.",
		strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "Cursor/beforeSubmitPrompt", Action: "blocked", Rules: rules, Field: "prompt"})

	out := beforeSubmitPromptOutput{Continue: false, UserMessage: msg}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

func passthrough(w io.Writer) error {
	_, _ = io.WriteString(w, "{}\n")
	return nil
}

// emitPausedNotice surfaces the paused banner via user_message + continue:true
// — additional_context isn't surfaced (forum 157141).
func emitPausedNotice(w io.Writer) error {
	banner := pause.Banner()
	if banner == "" {
		return passthrough(w)
	}
	out := beforeSubmitPromptOutput{Continue: true, UserMessage: banner}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

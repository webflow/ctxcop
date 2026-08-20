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

type compactInput struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	HookEventName  string `json:"hook_event_name"`
}

// preCompactOutput uses top-level fields (UserPromptSubmit family), not
// nested hookSpecificOutput. See docs/hook-contracts.md.
type preCompactOutput struct {
	Decision      string `json:"decision,omitempty"`
	Reason        string `json:"reason,omitempty"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

// PreCompact scans the pre-compaction transcript and warns on findings.
// The compaction summary inherits whatever the source contained, so any
// matching string in the summary should be treated as the original value.
// Never blocks — blocking compaction strands the user. Fail-open.
func PreCompact(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in compactInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if in.TranscriptPath == "" {
		return passthrough(w)
	}
	data, err := os.ReadFile(in.TranscriptPath)
	if err != nil {
		return passthrough(w)
	}
	// The transcript is untrusted content — do not honor inline allow/fixture
	// markers (issue #56).
	_, ruleIDs, err := redact.RedactToolOutput(string(data))
	if err != nil || len(ruleIDs) == 0 {
		audit.Log(audit.Entry{Tool: "PreCompact", Action: "clean"})
		return passthrough(w)
	}
	audit.Log(audit.Entry{Tool: "PreCompact", Action: "transcript-scan", Rules: ruleIDs, Count: len(ruleIDs)})
	msg := fmt.Sprintf(
		"ctxcop: about to compact a transcript that contains %d apparent secret-shape finding(s) (%s). "+
			"The compaction summary inherits whatever the original text contained — treat any %s-shaped "+
			"value in the resulting summary as if it were the unredacted secret. Don't echo it, don't write it, "+
			"and consider rotating any credential the summary references.",
		len(ruleIDs), strings.Join(ruleIDs, ", "), strings.Join(ruleIDs, "/"))
	out := preCompactOutput{SystemMessage: msg}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

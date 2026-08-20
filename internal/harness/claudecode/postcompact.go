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

// PostCompact has no decision field per spec; exit code is ignored.
type postCompactOutput struct {
	SystemMessage string `json:"systemMessage,omitempty"`
}

// PostCompact scans the post-compaction transcript and warns on
// credential-shape findings. PreCompact catches secrets in the source;
// PostCompact catches secrets the summarizer may have re-synthesized
// from previously-redacted content.
func PostCompact(r io.Reader, w io.Writer) error {
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
		audit.Log(audit.Entry{Tool: "PostCompact", Action: "clean"})
		return passthrough(w)
	}
	audit.Log(audit.Entry{Tool: "PostCompact", Action: "post-summary-scan", Rules: ruleIDs, Count: len(ruleIDs)})
	msg := fmt.Sprintf(
		"ctxcop: the post-compaction transcript contains %d apparent secret-shape finding(s) (%s). "+
			"If these surfaced in the compaction summary, the summarizer may have re-synthesized credential "+
			"patterns from previously-redacted content. Treat the affected segment as compromised: don't "+
			"propagate any %s-shaped value out of this context, and consider rotating the corresponding credential.",
		len(ruleIDs), strings.Join(ruleIDs, ", "), strings.Join(ruleIDs, "/"))
	out := postCompactOutput{SystemMessage: msg}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

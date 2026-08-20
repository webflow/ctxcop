package aider

import (
	"strings"
	"testing"
)

// TestPrimingCoversKeyConventions guards the SessionStart-equivalent
// text against silent drift. The priming file is the ONLY place
// Aider's model learns ctxcop's conventions, so the essential
// keywords must be present.
func TestPrimingCoversKeyConventions(t *testing.T) {
	for _, want := range []string{
		"ctxcop is watching this Aider session",
		"lint-cmd",
		"test-cmd",
		"UserPromptSubmit",
		"LiteLLM",
		"os.Getenv",
		"process.env",
		"<REDACTED",
		"audit log",
	} {
		if !strings.Contains(primingMarkdown, want) {
			t.Errorf("priming missing %q", want)
		}
	}
}

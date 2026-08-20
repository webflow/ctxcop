package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestUserPromptBlocksOnSecret guards the v0.1.0 leak-path bug: the handler
// previously emitted PreToolUse's nested hookSpecificOutput.permissionDecision
// shape, which Claude Code silently ignored for UserPromptSubmit. The correct
// contract is top-level `decision` + `reason`. Both keys are asserted by
// name so a future "improvement" that reverts the shape gets caught here.
func TestUserPromptBlocksOnSecret(t *testing.T) {
	in := `{"prompt":"please debug this, my key is ` + akia + ` and it stopped working"}`
	var out bytes.Buffer
	if err := UserPromptSubmit(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if m["decision"] != "block" {
		t.Errorf("expected top-level decision=block, got %v (full=%v)", m["decision"], m)
	}
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("must not nest under hookSpecificOutput — UserPromptSubmit uses top-level shape: %v", m)
	}
	reason, _ := m["reason"].(string)
	for _, want := range []string{"env var", "abstractly", "gitleaks:allow"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason missing %q: %q", want, reason)
		}
	}
}

func TestUserPromptCleanPasses(t *testing.T) {
	in := `{"prompt":"explain the difference between context and tokens"}`
	var out bytes.Buffer
	if err := UserPromptSubmit(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestUserPromptBadJSONPasses(t *testing.T) {
	var out bytes.Buffer
	if err := UserPromptSubmit(strings.NewReader("not json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough on bad JSON, got %q", got)
	}
}

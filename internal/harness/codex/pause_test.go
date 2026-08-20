package codex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webflow/ctxcop/internal/testenv"
)

// TestPauseHonoredAcrossCodexHandlers guards against the bug where
// `ctxcop pause` only paused Claude Code. Codex's preToolUse,
// postToolUse, and userPromptSubmit must all passthrough when the
// shared pause sentinel says paused.
func TestPauseHonoredAcrossCodexHandlers(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetHomeDir(t, tmp)
	dir := filepath.Join(tmp, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}

	assertPassthrough := func(name string, fn func() (string, error)) {
		t.Helper()
		got, err := fn()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.TrimSpace(got) != "{}" {
			t.Errorf("%s should passthrough when paused, got %q", name, got)
		}
	}

	assertPassthrough("preToolUse Bash w/ secret", func() (string, error) {
		in := `{"tool_name":"Bash","tool_input":{"command":"export KEY=` + akia + `"}}`
		var out bytes.Buffer
		err := PreToolUse(strings.NewReader(in), &out)
		return out.String(), err
	})
	assertPassthrough("postToolUse w/ secret", func() (string, error) {
		in := `{"tool_name":"Bash","tool_response":{"output":"key=` + akia + `"}}`
		var out bytes.Buffer
		err := PostToolUse(strings.NewReader(in), &out)
		return out.String(), err
	})
	t.Run("SessionStart prepends paused banner", func(t *testing.T) {
		var out bytes.Buffer
		if err := SessionStart(&out); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if !strings.Contains(body, "PAUSED") {
			t.Errorf("SessionStart should include paused banner: %q", body)
		}
		if !strings.Contains(body, "ctxcop is active in this Codex session") {
			t.Errorf("SessionStart should still carry the priming message: %q", body)
		}
	})

	// userPromptSubmit emits a non-blocking notice when paused (banner
	// via additionalContext) rather than {}. The user's prompt proceeds.
	t.Run("UserPromptSubmit emits paused notice, does not block", func(t *testing.T) {
		in := `{"prompt":"use ` + akia + `"}`
		var out bytes.Buffer
		if err := UserPromptSubmit(strings.NewReader(in), &out); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if strings.Contains(body, `"decision":"block"`) {
			t.Errorf("UserPromptSubmit should not block when paused: %q", body)
		}
		if !strings.Contains(body, "PAUSED") {
			t.Errorf("UserPromptSubmit should emit paused banner: %q", body)
		}
	})
}

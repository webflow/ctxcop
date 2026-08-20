package cursor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webflow/ctxcop/internal/testenv"
)

// TestPauseHonoredAcrossCursorHandlers guards against the bug where
// `ctxcop pause` only paused Claude Code. Cursor's preToolUse,
// postToolUse, and beforeSubmitPrompt must all passthrough when the
// shared pause sentinel says paused.
func TestPauseHonoredAcrossCursorHandlers(t *testing.T) {
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

	assertPassthrough("preToolUse Shell w/ secret", func() (string, error) {
		in := `{"tool_name":"Shell","tool_input":{"command":"export KEY=` + akia + `"}}`
		var out bytes.Buffer
		err := PreToolUse(strings.NewReader(in), &out)
		return out.String(), err
	})
	assertPassthrough("postToolUse w/ secret", func() (string, error) {
		in := `{"tool_name":"MCP:foo:bar","tool_output":{"data":"key=` + akia + `"}}`
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
		if !strings.Contains(body, "ctxcop is active in this Cursor session") {
			t.Errorf("SessionStart should still carry the priming message: %q", body)
		}
	})

	// beforeSubmitPrompt emits a non-blocking notice when paused —
	// continue:true plus user_message containing the banner — rather
	// than an empty {} passthrough. Forum 157141 (additional_context
	// not surfaced) is why we use user_message here.
	t.Run("beforeSubmitPrompt emits paused notice, does not block", func(t *testing.T) {
		in := `{"prompt":"use ` + akia + `"}`
		var out bytes.Buffer
		if err := BeforeSubmitPrompt(strings.NewReader(in), &out); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if strings.Contains(body, `"continue":false`) {
			t.Errorf("beforeSubmitPrompt should not block when paused: %q", body)
		}
		if !strings.Contains(body, "PAUSED") {
			t.Errorf("beforeSubmitPrompt should emit paused banner: %q", body)
		}
		if !strings.Contains(body, `"user_message"`) {
			t.Errorf("notice should use user_message field: %q", body)
		}
	})
}

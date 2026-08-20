package claudecode

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webflow/ctxcop/internal/testenv"
)

// TestPauseHonoredAcrossClaudeCodeHandlers extends the prior PreToolUse-
// only pause coverage to every Claude Code handler that produces a
// decision. PreToolUse already had its pause check; PostToolUse,
// UserPromptSubmit, Pre/PostCompact, and ElicitationResult did not, so
// `ctxcop pause` only partially silenced ctxcop. Each handler must now
// emit the empty-decision passthrough when paused.
func TestPauseHonoredAcrossClaudeCodeHandlers(t *testing.T) {
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

	assertPassthrough("PreToolUse Bash w/ secret", func() (string, error) {
		in := `{"tool_name":"Bash","tool_input":{"command":"echo ` + akia + `"}}`
		var out bytes.Buffer
		err := PreToolUse("/usr/bin/ctxcop", strings.NewReader(in), &out)
		return out.String(), err
	})
	assertPassthrough("PostToolUse w/ secret", func() (string, error) {
		in := `{"tool_name":"WebFetch","tool_response":{"data":"key=` + akia + `"}}`
		var out bytes.Buffer
		err := PostToolUse(strings.NewReader(in), &out)
		return out.String(), err
	})
	// UserPromptSubmit is the exception: when paused, it emits a non-
	// blocking notice via additionalContext instead of an empty
	// passthrough, so the user sees "ctxcop is paused" once per turn.
	// The user's prompt is NOT blocked (no decision field), and the
	// secret detection is intentionally skipped.
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
		if !strings.Contains(body, `"additionalContext"`) {
			t.Errorf("notice should use additionalContext field: %q", body)
		}
	})

	// SessionStart while paused prepends the banner to the priming
	// message so the user sees the paused state at session boot. The
	// priming itself is preserved underneath.
	t.Run("SessionStart prepends paused banner", func(t *testing.T) {
		var out bytes.Buffer
		if err := SessionStart(&out); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if !strings.Contains(body, "PAUSED") {
			t.Errorf("SessionStart should include paused banner: %q", body)
		}
		if !strings.Contains(body, "ctxcop is active in this session") {
			t.Errorf("SessionStart should still carry the priming message: %q", body)
		}
	})

	// PreCompact / PostCompact pass through when paused without reading
	// the transcript at all — we don't need a transcript on disk to
	// assert passthrough.
	assertPassthrough("PreCompact paused", func() (string, error) {
		in := `{"transcript_path":"/nonexistent","hook_event_name":"PreCompact"}`
		var out bytes.Buffer
		err := PreCompact(strings.NewReader(in), &out)
		return out.String(), err
	})
	assertPassthrough("PostCompact paused", func() (string, error) {
		in := `{"transcript_path":"/nonexistent","hook_event_name":"PostCompact"}`
		var out bytes.Buffer
		err := PostCompact(strings.NewReader(in), &out)
		return out.String(), err
	})
	assertPassthrough("ElicitationResult w/ secret", func() (string, error) {
		in := `{"server_name":"foo","tool_name":"bar","action":"accept","content":{"k":"` + akia + `"}}`
		var out bytes.Buffer
		err := ElicitationResult(strings.NewReader(in), &out)
		return out.String(), err
	})
}

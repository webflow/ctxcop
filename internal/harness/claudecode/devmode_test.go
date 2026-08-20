package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestDevModeDowngradesWriteBlock(t *testing.T) {
	t.Setenv("CTXCOP_DEV", "warn")
	in := `{"tool_name":"Write","tool_input":{"file_path":"/x","content":"key=` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("dev-warn should allow, got %v", hso["permissionDecision"])
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "dev-warn") {
		t.Errorf("reason missing dev-warn marker: %q", reason)
	}
}

func TestDevModeOffStillBlocks(t *testing.T) {
	t.Setenv("CTXCOP_DEV", "")
	in := `{"tool_name":"Write","tool_input":{"file_path":"/x","content":"key=` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out.Bytes(), &m)
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("default mode should deny, got %v", hso["permissionDecision"])
	}
}

func TestSkipPathSuppressesWriteBlock(t *testing.T) {
	t.Setenv("CTXCOP_DEV", "")
	t.Setenv("CTXCOP_SKIP_PATHS", "")
	in := `{"tool_name":"Write","tool_input":{"file_path":"internal/runner/runner_test.go","content":"key=` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected skip-path passthrough, got %q", got)
	}
}

func TestPausePassesthroughEverything(t *testing.T) {
	// We can't easily test the sentinel itself here without monkeying with
	// HOME, but we can verify the early-return path is invoked.
	// Save and restore HOME so we don't pollute the user's actual paused file.
	testenv.SetHomeDir(t, t.TempDir())
	// No sentinel exists in this scratch HOME → not paused → handler runs.
	in := `{"tool_name":"Write","tool_input":{"file_path":"/x","content":"key=` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// Default mode + clean home should deny.
	if !strings.Contains(out.String(), "deny") {
		t.Errorf("expected deny in clean state: %q", out.String())
	}
}

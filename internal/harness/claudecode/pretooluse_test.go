package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, b)
	}
	return m
}

func TestRewritesBashCommand(t *testing.T) {
	in := []byte(`{"tool_name":"Bash","tool_input":{"command":"aws sts get-caller-identity","description":"whoami"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	hso := got["hookSpecificOutput"].(map[string]any)
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName=%v", hso["hookEventName"])
	}
	// #47: a plain wrap must NOT assert a permissionDecision — "allow" would
	// bypass the user's own permission rules. updatedInput is applied on its
	// own; the user's rules still govern the rewritten command.
	if _, ok := hso["permissionDecision"]; ok {
		t.Errorf("unexpected permissionDecision on plain wrap: %v", hso["permissionDecision"])
	}
	ui := hso["updatedInput"].(map[string]any)
	cmd := ui["command"].(string)
	if !strings.Contains(cmd, "ctxcop run -- bash -c") {
		t.Errorf("expected bash -c wrap: %q", cmd)
	}
	if !strings.Contains(cmd, "aws sts get-caller-identity") {
		t.Errorf("original cmd missing: %q", cmd)
	}
	if ui["description"] != "whoami" {
		t.Errorf("description not preserved: %v", ui["description"])
	}
}

// TestRewritesShellBuiltin guards the bug where the rewrite tried to exec
// `export` directly. `export`, `cd`, `source`, `eval`, multi-line scripts,
// pipelines, and heredocs all require a shell to run; the rewrite must wrap
// in `bash -c`.
func TestRewritesShellBuiltin(t *testing.T) {
	multiline := "export AWS_PROFILE=foo\naws sts get-caller-identity"
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": multiline},
	})
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	cmd := got["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]any)["command"].(string)
	if !strings.Contains(cmd, "bash -c") {
		t.Errorf("multi-line script must be wrapped in bash -c: %q", cmd)
	}
	// The whole original (including the embedded newline) must survive
	// intact inside the single-quoted payload.
	if !strings.Contains(cmd, "export AWS_PROFILE=foo\naws sts get-caller-identity") {
		t.Errorf("original multi-line cmd not preserved: %q", cmd)
	}
}

func TestRewriteHandlesSingleQuotesInCommand(t *testing.T) {
	// awk one-liners and similar embed single quotes everywhere; the rewrite
	// must escape them so the bash -c argument stays well-formed.
	cmd := `awk 'NR==1{print $1}' /etc/hostname`
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": cmd},
	})
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	wrapped := got["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]any)["command"].(string)
	// Standard POSIX trick: end the single-quote, escape one ', restart.
	if !strings.Contains(wrapped, `'\''`) {
		t.Errorf("single-quote escape missing in wrap: %q", wrapped)
	}
}

func TestStreamForBackground(t *testing.T) {
	in := []byte(`{"tool_name":"Bash","tool_input":{"command":"tail -f /var/log/x","run_in_background":true}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	cmd := got["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]any)["command"].(string)
	if !strings.Contains(cmd, "run --stream --") {
		t.Errorf("missing --stream for background: %q", cmd)
	}
}

func TestPassthroughForNonBash(t *testing.T) {
	in := []byte(`{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestPassthroughOnBadJSON(t *testing.T) {
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader("not json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough on bad JSON, got %q", got)
	}
}

func TestNoDoubleWrap(t *testing.T) {
	in := []byte(`{"tool_name":"Bash","tool_input":{"command":"/usr/local/bin/ctxcop run -- aws sts"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected no rewrite for already-wrapped, got %q", got)
	}
}

func TestSpaceInBinaryPath(t *testing.T) {
	in := []byte(`{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/Users/me/My Tools/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	cmd := got["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]any)["command"].(string)
	if !strings.HasPrefix(cmd, "'/Users/me/My Tools/ctxcop'") {
		t.Errorf("path not quoted: %q", cmd)
	}
}
